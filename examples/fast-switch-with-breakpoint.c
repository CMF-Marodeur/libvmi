/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Author: Mathieu Tarral (mathieu.tarral@ssi.gouv.fr)
 *
 * This file is part of LibVMI.
 *
 * LibVMI is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * LibVMI is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with LibVMI.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <inttypes.h>
#include <signal.h>
#include <time.h> 
#include <libvmi/libvmi.h>
#include <libvmi/events.h>

//Includes for fast switch example
#include <libvmi/slat.h>
#include <xenctrl.h>

static int systemCr3Events = 0;
static int unwantedCr3Events = 0;
static addr_t targetCr3;
static int interrupted = 0;
uint16_t view_x = 0;
uint16_t view_rw = 0;
uint64_t vm_id = 0;
static void close_handler(int sig)
{
    interrupted = sig;
}

struct process_return{
    addr_t eprocess_base;
    pid_t pid;
};

event_response_t cr3_callback_with_switching(vmi_instance_t vmi, vmi_event_t *event)
{
    (void)vmi;
    if(event->reg_event.value == targetCr3)
    {
        systemCr3Events++;
        if( VMI_FAILURE == vmi_slat_switch(vmi, view_x))
        {
            printf("Could not switch to view_x.\n");
        }
    }
    else
    {
        unwantedCr3Events++;
        if(event->reg_event.previous == targetCr3)
        {
            if( VMI_FAILURE == vmi_slat_switch(vmi, 0))
            {
                printf("Could not switch to view_rw.\n");
            }
        }
    } 
    
    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t cr3_callback_only_counting(vmi_instance_t vmi, vmi_event_t *event)
{
    (void)vmi;
    if(event->reg_event.value == targetCr3)
    {
        systemCr3Events++;

    }
    else
    {
        unwantedCr3Events++;
    } 
    
    return VMI_EVENT_RESPONSE_NONE;
}

int setup_fast_switch(xc_interface* xc, vmi_instance_t vmi, uint targetCr3)
{
    for (uint i = 0; i < vmi_get_num_vcpus(vmi); i++)
    {
        printf("Setting fast switch for vcpu %d\n", i);
        errno = 0;
        int rc = xc_altp2m_add_fast_switch(xc, vm_id, i, targetCr3, view_rw, view_x);
        if(rc < 0)
        {
            printf("add fast switch failed: %d\n", rc);
            int bla = errno;
            printf("xenctrl last error code: %d\n", bla);
            printf("xenctrl error message: %s\n", strerror(bla));
            return 1;
        }
    }
    
    return 0;
}

int altp2m_setup(xc_interface* xc, vmi_instance_t vmi) {
    uint64_t vm_id = vmi_get_vmid(vmi);
    if (vm_id == VMI_INVALID_DOMID) {
        printf("Unable to fetch vm id.\n");
        return 1;
    }
    // grab current value of ALTP2M.
    uint64_t current_altp2m;
    if (xc_hvm_param_get(xc, vm_id, HVM_PARAM_ALTP2M, &current_altp2m) < 0)
    {
        printf("Failed to get HVM_PARAM_ALTP2M.\n");
        return 1;
    } else {
        printf("current_altp2m = %lu\n", current_altp2m);
    }
    // is ALTP2M not at external mode? turn it on.
    if (current_altp2m != XEN_ALTP2M_external &&
        xc_hvm_param_set(xc, vm_id, HVM_PARAM_ALTP2M, XEN_ALTP2M_external) < 0)
    {
        printf("Failed to set HVM_PARAM_ALTP2M.\n");
        return 1;
    }

    //create second slat for fast switch
    if( VMI_FAILURE == vmi_slat_set_domain_state(vmi, true))
    {
        printf("Could not enable slat. Aborting");
        return 1;
    }

    if( VMI_FAILURE == vmi_slat_create(vmi, &view_rw))
    {
        printf("Could not create view_rw. Aborting\n");
        return 1;
    }
    printf("view_rw is %d\n", view_rw);

    if( VMI_FAILURE == vmi_slat_create(vmi, &view_x))
    {
        printf("Could not create view_x. Aborting\n");
        return 1;
    }
    printf("view_x is %d\n", view_x);

    return 0;
}

int measure_cr3_switches(vmi_instance_t vmi, vmi_event_t* cr3_event)
{
    int target_seconds = 30;
    time_t start_time,end_time;
    status_t status = VMI_FAILURE;


    // register event
    if (vmi_register_event(vmi, cr3_event) == VMI_FAILURE)
        return -1;

    for(int i = 0; i<5; i++)
    {
        systemCr3Events = 0;
        unwantedCr3Events = 0;
        time (&start_time);
        time (&end_time);
        printf("Waiting for events in iteration %d. Seconds: %d\n", i, target_seconds);
        while (!interrupted && (difftime(end_time, start_time) < target_seconds)) 
        {
            time (&end_time);
            status = vmi_events_listen(vmi, 500);
            if (status == VMI_FAILURE)
                printf("Failed to listen on events\n");
        }
        printf ("Got %d cr3 events for %x in %d sec. %d other events.\n", systemCr3Events, (uint)targetCr3, target_seconds, unwantedCr3Events );
    }
    vmi_clear_event(vmi, cr3_event, NULL);
    return 0;
}

struct process_return get_suitable_process_eprocess_base(vmi_instance_t vmi)
{
    addr_t list_head = 0, cur_list_entry = 0, next_list_entry = 0;
    addr_t current_process = 0;
    char *procname = NULL;
    vmi_pid_t pid = 0;
    status_t status = VMI_FAILURE;
    unsigned long tasks_offset = 0, pid_offset = 0, name_offset = 0;
    addr_t eprocess_base = 0;

    struct process_return suitable_process={.pid = 0, .eprocess_base = 0};

    if ( VMI_FAILURE == vmi_get_offset(vmi, "win_tasks", &tasks_offset) )
        goto error_exit;
    if ( VMI_FAILURE == vmi_get_offset(vmi, "win_pname", &name_offset) )
        goto error_exit;
    if ( VMI_FAILURE == vmi_get_offset(vmi, "win_pid", &pid_offset) )
        goto error_exit;

    printf("tasks_offset %u\n", tasks_offset);
    printf("tasks_offset %u\n", name_offset);
    printf("tasks_offset %u\n", pid_offset);

    // find PEPROCESS PsInitialSystemProcess
    if (VMI_FAILURE == vmi_read_addr_ksym(vmi, "PsActiveProcessHead", &list_head)) {
        printf("Failed to find PsActiveProcessHead\n");
        goto error_exit;
    }

    cur_list_entry = list_head;
    if (VMI_FAILURE == vmi_read_addr_va(vmi, cur_list_entry, 0, &next_list_entry)) {
        printf("Failed to read next pointer in loop at %"PRIx64"\n", cur_list_entry);
        goto error_exit;
    }

    /* walk the task list */
    bool found_suitable_process = false;
    while (!found_suitable_process) {

        current_process = cur_list_entry - tasks_offset;

        /* Note: the task_struct that we are looking at has a lot of
         * information.  However, the process name and id are burried
         * nice and deep.  Instead of doing something sane like mapping
         * this data to a task_struct, I'm just jumping to the location
         * with the info that I want.  This helps to make the example
         * code cleaner, if not more fragile.  In a real app, you'd
         * want to do this a little more robust :-)  See
         * include/linux/sched.h for mode details */

        /* NOTE: _EPROCESS.UniqueProcessId is a really VOID*, but is never > 32 bits,
         * so this is safe enough for x64 Windows for example purposes */
        vmi_read_32_va(vmi, current_process + pid_offset, 0, (uint32_t*)&pid);

        procname = vmi_read_str_va(vmi, current_process + name_offset, 0);

        if (!procname) {
            printf("Failed to find procname\n");
            goto error_exit;
        }

        /* print out the process name */
        printf("[%5d] %s (struct addr:%"PRIx64")\n", pid, procname, current_process);
        if (procname) {
            if(!strcmp(procname, "explorer.exe"))
            {
                printf("found explorer.exe\n");
                found_suitable_process = true;
                suitable_process.eprocess_base = current_process;
                suitable_process.pid = pid;
            }
            free(procname);
            procname = NULL;
        }

        /* follow the next pointer */
        cur_list_entry = next_list_entry;
        status = vmi_read_addr_va(vmi, cur_list_entry, 0, &next_list_entry);
        if (status == VMI_FAILURE) {
            printf("Failed to read next pointer in loop at %"PRIx64"\n", cur_list_entry);
            goto error_exit;
        }

        if (next_list_entry == list_head) {
            break;
        } 
    };

    error_exit:
    return suitable_process;
}

addr_t get_ntdll_base_address(vmi_instance_t vmi, struct process_return suitable_process)
{
    addr_t module_list_base = 0;

    addr_t peb = 0;
    if (VMI_FAILURE == vmi_read_addr_va(vmi, suitable_process.eprocess_base + 0x1b0, 0, &peb)) {
        printf("Failed to read PEB pointer from %"PRIx64"\n", suitable_process.eprocess_base + 0x1b0);
    goto error_exit;
    }
    printf("PEB pointer %"PRIx64"\n", peb);


    addr_t ldr_pointer = 0;
    if (VMI_FAILURE == vmi_read_addr_va(vmi, peb + 0xc, suitable_process.pid, &ldr_pointer)) {
        printf("Failed to read LDR pointer from %"PRIx64"\n", peb + 0xc);
    goto error_exit;
    }
    printf("LDR pointer %"PRIx64"\n", ldr_pointer);

    module_list_base = ldr_pointer + 0xc;

    addr_t next_module = module_list_base;
    bool ntdll_found = false;
    addr_t ntdll_base_address = 0;
    /* walk the module list */
    while (!ntdll_found) {

        /* follow the next pointer */
        addr_t tmp_next = 0;

        vmi_read_addr_va(vmi, next_module, suitable_process.pid, &tmp_next);

        /* if we are back at the list head, we are done */
        if (module_list_base == tmp_next) {
            break;
        }

        addr_t ldr_data_table_entry = 0;
        if (VMI_FAILURE == vmi_read_addr_va(vmi, tmp_next, suitable_process.pid, &ldr_data_table_entry)) {
            printf("Failed to read LDR_DATA_TABLE_ENTRY from %"PRIx64"\n", tmp_next);
        goto error_exit;
        }
        printf("LDR_DATA_TABLE_ENTRY %"PRIx64"\n", ldr_data_table_entry);

        unicode_string_t *us = NULL;

        /*
            * The offset 0x58 and 0x2c is the offset in the _LDR_DATA_TABLE_ENTRY structure
            * to the BaseDllName member.
            * These offset values are stable (at least) between XP and Windows 7.
            */

        if (VMI_PM_IA32E == vmi_get_page_mode(vmi, 0)) {
            us = vmi_read_unicode_str_va(vmi, ldr_data_table_entry + 0x58, suitable_process.pid);
        } else {
            us = vmi_read_unicode_str_va(vmi, ldr_data_table_entry + 0x2c, suitable_process.pid);
        }

        unicode_string_t out = { 0 };
        //         both of these work
        if (us &&
                VMI_SUCCESS == vmi_convert_str_encoding(us, &out,
                        "UTF-8")) {
            printf("%s\n", out.contents);
            //            if (us &&
            //                VMI_SUCCESS == vmi_convert_string_encoding (us, &out, "WCHAR_T")) {
            //                printf ("%ls\n", out.contents);
            if(!strcmp((const char*)out.contents, "ntdll.dll"))
            {
                printf("found ntdll\n");
                if (VMI_FAILURE == vmi_read_addr_va(vmi, ldr_data_table_entry + 0x18, suitable_process.pid, &ntdll_base_address)) {
                    printf("Failed to read ntdll_base_address from %"PRIx64"\n", ldr_data_table_entry + 0x18);
                goto error_exit;
                }
                printf("ntdll_base_address %"PRIx64"\n", ntdll_base_address);
                ntdll_found = true;
            }
            free(out.contents);
        }   // if
        if (us)
        {
            vmi_free_unicode_str(us);
        }
        next_module = tmp_next;
    }
    error_exit:
    return ntdll_base_address;
}

int main (int argc, char **argv)
{
    vmi_instance_t vmi = {0};
    vmi_mode_t mode = {0};
    vmi_init_data_t *init_data = NULL;
    int retcode = 1;

    /* this is the VM or file that we are looking at */
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <vmname> [<socket>]\n", argv[0]);
        return retcode;
    }

    char *name = argv[1];

    if (argc == 3) {
        char *path = argv[2];

        // fill init_data
        init_data = malloc(sizeof(vmi_init_data_t) + sizeof(vmi_init_data_entry_t));
        init_data->count = 1;
        init_data->entry[0].type = VMI_INIT_DATA_KVMI_SOCKET;
        init_data->entry[0].data = strdup(path);
    }

    if (VMI_FAILURE == vmi_get_access_mode(NULL, (void*)name, VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS, init_data, &mode)) {
        fprintf(stderr, "Failed to get access mode\n");
        goto error_exit;
    }

    /* initialize the libvmi library */
    uint8_t config_type = VMI_CONFIG_GLOBAL_FILE_ENTRY;
    void *config = NULL;
    if (VMI_FAILURE == vmi_init_complete(&vmi, name, VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS, init_data, config_type, config, NULL)) {
        printf("Failed to init LibVMI library.\n");
        goto error_exit;
    }

    xc_interface* xc = xc_interface_open(0, 0, 0);
    if(xc == NULL)
    {
        printf("Could not get xen interface. Aborting");
        goto error_exit;
    }

    struct sigaction act;
    /* for a clean exit */
    act.sa_handler = close_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT,  &act, NULL);
    sigaction(SIGALRM, &act, NULL);

    /* pause the vm for consistent memory access */
    if (vmi_pause_vm(vmi) != VMI_SUCCESS) {
        printf("Failed to pause VM\n");
        goto error_exit;
    }

    vm_id = vmi_get_vmid(vmi);
    if (vm_id == VMI_INVALID_DOMID) {
        printf("Unable to fetch vm id.\n");
         goto error_exit;
    }


    vmi_event_t cr3_event = {0};
    cr3_event.version = VMI_EVENTS_VERSION;
    cr3_event.type = VMI_EVENT_REGISTER;
    cr3_event.callback = cr3_callback_with_switching;
    cr3_event.reg_event.reg = CR3;
    cr3_event.reg_event.in_access = VMI_REGACCESS_W;

    printf("Getting cr3\n");
    // get system cr3
    if (vmi_pid_to_dtb(vmi, 0x4, &targetCr3) == VMI_FAILURE)
    {
        printf("Could not get CR3, Aborting");
        goto error_exit;
    }
    printf("Got targetCr3: 0x%x\n", (uint)targetCr3);
    
    if (altp2m_setup(xc, vmi)) {
        goto error_exit;
    }

    struct process_return suitable_process = get_suitable_process_eprocess_base(vmi);
    addr_t ntdll_base_address = get_ntdll_base_address(vmi, suitable_process);

    if (vmi_resume_vm(vmi) ==  VMI_FAILURE)
        goto error_exit;

    // if( measure_cr3_switches(vmi, &cr3_event) <0)
    // {
    //     printf("Could not measure cr3 switches");
    //     goto error_exit;
    // }
    
    // bool use_fast_switch = true;
    // if(use_fast_switch)
    // {
    //     if (setup_fast_switch(xc, vmi, targetCr3))
    //     {
    //         printf("Could not setup fast switch\n");
    //         goto error_exit;
    //     }
    //     printf("########### fast switch successfully enabled ########### \n");
    // }

    // cr3_event.callback = cr3_callback_only_counting;
    // if( measure_cr3_switches(vmi, &cr3_event) <0)
    // {
    //     printf("Could not measure cr3 switches");
    //     goto error_exit;
    // }

    retcode = 0;
error_exit:
    vmi_clear_event(vmi, &cr3_event, NULL);
    for (uint i = 0; i < vmi_get_num_vcpus(vmi); i++)
    {
        xc_altp2m_remove_fast_switch(xc, vm_id, i, targetCr3);
    }

    vmi_slat_destroy(vmi, view_rw);
    vmi_slat_destroy(vmi, view_x);
    
    // close xen access handle if open.
    if(xc != NULL)
    {
        xc_interface_close(xc);
    }

    /* cleanup any memory associated with the LibVMI instance */
    vmi_destroy(vmi);

    if (init_data) {
        free(init_data->entry[0].data);
        free(init_data);
    }

    return retcode;
}
