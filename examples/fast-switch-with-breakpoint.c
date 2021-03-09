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

#define PAGE_RANGE 12
#define PAGE_SIZE 4096

char BREAKPOINT = 0xcc;
vmi_event_t int_event;
vmi_event_t cr3_event = {0};
vmi_event_t sstep_event = {0};
static addr_t interrupt_PA = 0;
static addr_t last_page =0;
static uint8_t interrupt_original_value = 0;
static addr_t targetCr3;
static int interrupted = 0;
uint16_t view_x = 0;
uint16_t view_rw = 0;
uint64_t vm_id = 0;

static const char target_process[] = "APIHammering2.e";
static const char target_dll[] = "kernel32.dll";
static const char targetFunction[] = "GetCurrentProcessId";
static int target_seconds = 30;
static bool use_cr3_guard = false;

static bool isTargetCr3 = false;
static uint64_t wrong_cr3_breakpoint_hits = 0;

static void close_handler(int sig)
{
    interrupted = sig;
}

struct process_return
{
    addr_t eprocess_base;
    pid_t pid;
    addr_t dtb;
};

struct interrupt_data
{
    addr_t sym_vaddr;
    addr_t sym_pa;
    char saved_opcode;
    uint64_t hit_count;
};
static struct interrupt_data interrupt_struct;

struct ShadowPage
{
    addr_t read_write, execute;
    uint16_t vcpu;
    size_t refs;
};
static struct ShadowPage shadow_page;

event_response_t breakpoint_cb(vmi_instance_t vmi, vmi_event_t *event)
{
    if (!event->data) {
        fprintf(stderr, "Empty event data in breakpoint callback !\n");
        interrupted = true;
        return VMI_EVENT_RESPONSE_NONE;
    }
    // get back callback data struct
    struct interrupt_data *cb_data = (struct interrupt_data*)event->data;

    if ( !event->interrupt_event.insn_length )
        event->interrupt_event.insn_length = 1;

    if (event->x86_regs->rip != cb_data->sym_vaddr)
    {
        // not our breakpoint
        event->interrupt_event.reinject = 1;
        printf("Not our breakpoint. Reinjecting INT3\n");
        return VMI_EVENT_RESPONSE_NONE;
    }
    else 
    {
        if(isTargetCr3)
        {
            // printf("[%"PRIu32"] Target breakpoint hit. Count: %"PRIu64"\n", event->vcpu_id, cb_data->hit_count);
            cb_data->hit_count++;
        }
        else
        {
            // printf("[%"PRIu32"] Wrong CR3 breakpoint hit. Count: %"PRIu64"\n", event->vcpu_id, wrong_cr3_breakpoint_hits);
            wrong_cr3_breakpoint_hits++;
        }
        event->interrupt_event.reinject = 0;

        // write saved opcode
        if (VMI_FAILURE == vmi_write_pa(vmi, cb_data->sym_pa, sizeof(cb_data->saved_opcode), &cb_data->saved_opcode, NULL)) {
            printf("Failed to write back original opcode at 0x%" PRIx64 "\n", cb_data->sym_pa);
            interrupted = true;
            return VMI_EVENT_RESPONSE_NONE;
        }
        // enable singlestep
        return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;
    }

    return 0;
}

event_response_t single_step_cb(vmi_instance_t vmi, vmi_event_t *event)
{
    if (!event->data) {
        printf("Empty event data in singlestep callback !\n");
        interrupted = true;
        return VMI_EVENT_RESPONSE_NONE;
    }

    // get back callback data struct
    struct interrupt_data *cb_data = (struct interrupt_data*)event->data;

    // restore breakpoint
    if (VMI_FAILURE == vmi_write_pa(vmi, cb_data->sym_pa, sizeof(BREAKPOINT), &BREAKPOINT, NULL)) {
        printf("Failed to write breakpoint at 0x%" PRIx64 "\n",cb_data->sym_pa);
        interrupted = true;
        return VMI_EVENT_RESPONSE_NONE;
    }

    // disable singlestep
    return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;
}

void restore_original_value(vmi_instance_t vmi)
{
    
    if (VMI_FAILURE == vmi_write_8_pa(vmi, interrupt_PA, &interrupt_original_value)) 
    {
        printf("Failed to write original value %"PRIx8" to PA %"PRIx64"\n", interrupt_original_value, interrupt_PA);
    }
}

void set_interrupt_event(vmi_instance_t vmi)
{
   if (VMI_FAILURE == vmi_write_pa(vmi, interrupt_PA, sizeof(BREAKPOINT), &BREAKPOINT, NULL)) 
    {
        printf("Failed to write interrupt value %"PRIx8" to PA %"PRIx64"\n", BREAKPOINT, interrupt_PA);
    }
}

event_response_t cr3_callback_overwriting_interrupt_event(vmi_instance_t vmi, vmi_event_t *event)
{
    if(event->reg_event.value == targetCr3)
    {
        //printf("[%"PRIu32"] CR3: 0x%" PRIx64 " writing 0x%"PRIx8" at 0x%" PRIx64 "\n", event->vcpu_id, event->reg_event.value, BREAKPOINT, interrupt_PA);

        set_interrupt_event(vmi);
        isTargetCr3 = true;
    }
    else
    {
        //printf("[%"PRIu32"] CR3: 0x%" PRIx64 " writing 0x%"PRIx8" at 0x%" PRIx64 "\n", event->vcpu_id, event->reg_event.value, interrupt_original_value, interrupt_PA);

        restore_original_value(vmi);
        isTargetCr3 = false;
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

struct process_return get_suitable_process_eprocess_base(vmi_instance_t vmi)
{
    addr_t list_head = 0, cur_list_entry = 0, next_list_entry = 0;
    addr_t current_process = 0;
    char *procname = NULL;
    vmi_pid_t pid = 0;
    status_t status = VMI_FAILURE;
    unsigned long tasks_offset = 0, pid_offset = 0, name_offset = 0;

    struct process_return suitable_process={.pid = 0, .eprocess_base = 0};

    if ( VMI_FAILURE == vmi_get_offset(vmi, "win_tasks", &tasks_offset) )
        goto error_exit;
    if ( VMI_FAILURE == vmi_get_offset(vmi, "win_pname", &name_offset) )
        goto error_exit;
    if ( VMI_FAILURE == vmi_get_offset(vmi, "win_pid", &pid_offset) )
        goto error_exit;

    printf("tasks_offset %lu\n", tasks_offset);
    printf("tasks_offset %lu\n", name_offset);
    printf("tasks_offset %lu\n", pid_offset);

    // find PEPROCESS PsInitialSystemProcess
    if (VMI_FAILURE == vmi_read_addr_ksym(vmi, "PsActiveProcessHead", &list_head)) 
    {
        printf("Failed to find PsActiveProcessHead\n");
        goto error_exit;
    }

    cur_list_entry = list_head;
    if (VMI_FAILURE == vmi_read_addr_va(vmi, cur_list_entry, 0, &next_list_entry)) 
    {
        printf("Failed to read next pointer in loop at %"PRIx64"\n", cur_list_entry);
        goto error_exit;
    }

    /* walk the task list */
    bool found_suitable_process = false;
    while (!found_suitable_process) 
    {
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

        if (!procname) 
        {
            printf("Failed to find procname\n");
            goto error_exit;
        }

        /* print out the process name */
        printf("[%5d] %s (struct addr:%"PRIx64")\n", pid, procname, current_process);
        if (procname) 
        {
            if(!strcmp(procname, target_process))
            {
                printf("found %s\n", target_process);

                printf("Getting dtb\n");
                addr_t dtb;
                // get system cr3
                if (vmi_pid_to_dtb(vmi, pid, &dtb) == VMI_FAILURE)
                {
                    printf("Could not get CR3, Aborting");
                    break;
                }
                printf("Got dtb: 0x%x\n", (uint)dtb);
                found_suitable_process = true;
                suitable_process.eprocess_base = current_process;
                suitable_process.pid = pid;
                suitable_process.dtb = dtb;
            }
            free(procname);
            procname = NULL;
        }

        /* follow the next pointer */
        cur_list_entry = next_list_entry;
        status = vmi_read_addr_va(vmi, cur_list_entry, 0, &next_list_entry);
        if (status == VMI_FAILURE) 
        {
            printf("Failed to read next pointer in loop at %"PRIx64"\n", cur_list_entry);
            goto error_exit;
        }

        if (next_list_entry == list_head) 
        {
            break;
        } 
    };

    error_exit:
    return suitable_process;
}

addr_t get_dll_base_address(vmi_instance_t vmi, struct process_return suitable_process, const char* target_dll)
{
    addr_t dll_base_address = 0;
    addr_t module_list_base = 0;

    addr_t peb = 0;
    if (VMI_FAILURE == vmi_read_addr_va(vmi, suitable_process.eprocess_base + 0x1b0, 0, &peb)) 
    {
        printf("Failed to read PEB pointer from %"PRIx64"\n", suitable_process.eprocess_base + 0x1b0);
        goto error_exit;
    }
    printf("PEB pointer %"PRIx64"\n", peb);


    addr_t ldr_pointer = 0;
    if (VMI_FAILURE == vmi_read_addr_va(vmi, peb + 0xc, suitable_process.pid, &ldr_pointer)) 
    {
        printf("Failed to read LDR pointer from %"PRIx64"\n", peb + 0xc);
        goto error_exit;
    }
    printf("LDR pointer %"PRIx64"\n", ldr_pointer);

    module_list_base = ldr_pointer + 0xc;

    addr_t next_module = module_list_base;
    bool dll_found = false;
    /* walk the module list */
    while (!dll_found) 
    {
        /* follow the next pointer */
        addr_t tmp_next = 0;

        vmi_read_addr_va(vmi, next_module, suitable_process.pid, &tmp_next);

        /* if we are back at the list head, we are done */
        if (module_list_base == tmp_next) 
        {
            break;
        }

        addr_t ldr_data_table_entry = 0;
        if (VMI_FAILURE == vmi_read_addr_va(vmi, tmp_next, suitable_process.pid, &ldr_data_table_entry)) 
        {
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

        if (VMI_PM_IA32E == vmi_get_page_mode(vmi, 0)) 
        {
            us = vmi_read_unicode_str_va(vmi, ldr_data_table_entry + 0x58, suitable_process.pid);
        } 
        else 
        {
            us = vmi_read_unicode_str_va(vmi, ldr_data_table_entry + 0x2c, suitable_process.pid);
        }

        unicode_string_t out = { 0 };
        //         both of these work
        if (us &&
                VMI_SUCCESS == vmi_convert_str_encoding(us, &out,
                        "UTF-8")) 
        {
            printf("%s\n", out.contents);
            //            if (us &&
            //                VMI_SUCCESS == vmi_convert_string_encoding (us, &out, "WCHAR_T")) {
            //                printf ("%ls\n", out.contents);
            if(!strcmp((const char*)out.contents, target_dll))
            {
                printf("found %s\n", target_dll);
                if (VMI_FAILURE == vmi_read_addr_va(vmi, ldr_data_table_entry + 0x18, suitable_process.pid, &dll_base_address)) 
                {
                    printf("Failed to read dll_base_address from %"PRIx64"\n", ldr_data_table_entry + 0x18);
                    goto error_exit;
                }
                printf("%s base_address %"PRIx64"\n", target_dll, dll_base_address);
                dll_found = true;
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
    return dll_base_address;
}

addr_t get_function_va(vmi_instance_t vmi, addr_t process_cr3, addr_t dll_base_address,const char* function_name)
{
    addr_t function_va = 0;
    access_context_t ctx = 
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = process_cr3,
        .addr = dll_base_address
    };
    if (VMI_FAILURE == vmi_translate_sym2v(vmi, &ctx, function_name, &function_va)) 
    {
        printf("Failed to get %s from process %"PRIx64" with dll_base_address %"PRIx64"\n", function_name, process_cr3, dll_base_address);
        goto error_exit;
    }

    printf("Address for %s: %"PRIx64"\n",function_name, function_va);

    error_exit:
    return function_va;
}

status_t CreateNewPage(xc_interface* xc, uint64_t vmid, uint64_t *addr)
{
    int rc = xc_domain_populate_physmap_exact(xc, vmid, 1, 0, 0, addr);

    if(rc < 0)
        return VMI_FAILURE;
    else
        return VMI_SUCCESS;
}

status_t DestroyPage(xc_interface* xc, uint64_t vmid, uint64_t *addr)
{
    int rc = xc_domain_decrease_reservation_exact(xc, vmid, 1, 0, addr);

    if(rc < 0)
        return VMI_FAILURE;
    else
        return VMI_SUCCESS;
}

uint64_t AllocatePage(xc_interface* xc, vmi_instance_t vmi, uint64_t vmid)
{
    addr_t new_page = ++last_page;
    if (CreateNewPage(xc, vmid, &new_page) != VMI_SUCCESS)
    {
        //TODO: Error Handling
    }    
    
    // refresh the cached end of physical memory.
    vmi_get_max_physical_address(vmi);
    
    return new_page;
}

int main (int argc, char **argv)
{
    vmi_instance_t vmi = {0};
    vmi_mode_t mode = {0};
    vmi_init_data_t *init_data = NULL;
    int retcode = 1;

    /* this is the VM or file that we are looking at */
    if (argc < 2) 
    {
        fprintf(stderr, "Usage: %s <vmname> [<socket>]\n", argv[0]);
        return retcode;
    }

    char *name = argv[1];

    if (argc == 3) 
    {
        char *path = argv[2];

        // fill init_data
        init_data = malloc(sizeof(vmi_init_data_t) + sizeof(vmi_init_data_entry_t));
        init_data->count = 1;
        init_data->entry[0].type = VMI_INIT_DATA_KVMI_SOCKET;
        init_data->entry[0].data = strdup(path);
    }

    if (VMI_FAILURE == vmi_get_access_mode(NULL, (void*)name, VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS, init_data, &mode)) 
    {
        fprintf(stderr, "Failed to get access mode\n");
        goto error_exit;
    }

    /* initialize the libvmi library */
    uint8_t config_type = VMI_CONFIG_GLOBAL_FILE_ENTRY;
    void *config = NULL;
    if (VMI_FAILURE == vmi_init_complete(&vmi, name, VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS, init_data, config_type, config, NULL)) 
    {
        printf("Failed to init LibVMI library.\n");
        goto error_exit;
    }

    /* pause the vm for consistent memory access */
    if (vmi_pause_vm(vmi) != VMI_SUCCESS) 
    {
        printf("Failed to pause VM\n");
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

    struct process_return suitable_process = get_suitable_process_eprocess_base(vmi);
    targetCr3 = suitable_process.dtb;

    addr_t ntdll_base_address = get_dll_base_address(vmi, suitable_process, target_dll);
    addr_t function_va = get_function_va(vmi, suitable_process.dtb, ntdll_base_address, targetFunction);

   if (VMI_FAILURE == vmi_translate_uv2p(vmi, function_va, suitable_process.pid, &interrupt_PA)) 
    {
        fprintf(stderr, "Could not convert VA %"PRIx64" for PID %u\n", function_va, suitable_process.pid);
        goto error_exit;
    }

    if (VMI_FAILURE == vmi_read_8_va(vmi, function_va, suitable_process.pid, &interrupt_original_value)) 
    {
        fprintf(stderr, "Failed to read opcode\n");
        goto error_exit;
    }

    if(use_cr3_guard)
    {
        // Init CR3 Event
        cr3_event.version = VMI_EVENTS_VERSION;
        cr3_event.type = VMI_EVENT_REGISTER;
        cr3_event.callback = cr3_callback_overwriting_interrupt_event;
        cr3_event.reg_event.reg = CR3;
        cr3_event.reg_event.in_access = VMI_REGACCESS_W;

        if( VMI_FAILURE == vmi_register_event(vmi,&cr3_event))
        {
            printf("Failed to init cr3 event\n");
            goto error_exit;
        }

        struct interrupt_data interrupt = 
        {
                .saved_opcode = interrupt_original_value,
                .sym_vaddr = function_va,
                .sym_pa = interrupt_PA,
                .hit_count = 0
        };
        interrupt_struct = interrupt;

        // register int3 event
        memset(&int_event, 0, sizeof(vmi_event_t));
        int_event.version = VMI_EVENTS_VERSION;
        int_event.type = VMI_EVENT_INTERRUPT;
        int_event.interrupt_event.intr = INT3;
        int_event.callback = breakpoint_cb;

        int_event.data = (void*)&interrupt_struct;

        printf("Register interrupt event\n");
        if (VMI_FAILURE == vmi_register_event(vmi, &int_event)) {
            fprintf(stderr, "Failed to register interrupt event\n");
            goto error_exit;
        }

        // get number of vcpus
        unsigned int num_vcpus = vmi_get_num_vcpus(vmi);

        // register singlestep event
        // disabled by default
        sstep_event.version = VMI_EVENTS_VERSION;
        sstep_event.type = VMI_EVENT_SINGLESTEP;
        sstep_event.callback = single_step_cb;
        sstep_event.ss_event.enable = false;
        // allow singlestep on all VCPUs
        for (unsigned int vcpu=0; vcpu < num_vcpus; vcpu++)
            SET_VCPU_SINGLESTEP(sstep_event.ss_event, vcpu);
        // pass struct bp_cb_data
        sstep_event.data = (void*)&interrupt_struct;

        printf("Register singlestep event\n");
        if (VMI_FAILURE == vmi_register_event(vmi, &sstep_event)) {
            fprintf(stderr, "Failed to register singlestep event\n");
            goto error_exit;
        }

    }
    else
    {
        vm_id = vmi_get_vmid(vmi);
        if (vm_id == VMI_INVALID_DOMID) 
        {
            printf("Unable to fetch vm id.\n");
            goto error_exit;
        }
        
        if (altp2m_setup(xc, vmi)) 
        {
            goto error_exit;
        }

        if (setup_fast_switch(xc, vmi, targetCr3))
        {
            printf("Could not setup fast switch\n");
            goto error_exit;
        }

        //init shadowpage
        addr_t max_gfn;
        xc_domain_maximum_gpfn(xc, vm_id, &max_gfn);
        AllocatePage(xc, vmi, vm_id);

        shadow_page.read_write = interrupt_PA >> PAGE_RANGE;
        shadow_page.execute = max_gfn >> PAGE_RANGE;

        // copy over page contents to shadow page.
        uint8_t buffer[PAGE_SIZE];
        if (vmi_read_pa(vmi, shadow_page.read_write << PAGE_RANGE, PAGE_SIZE, &buffer, NULL) != VMI_SUCCESS)
        {
            goto error_exit;
        }
        if (vmi_write_pa(vmi, shadow_page.execute << PAGE_RANGE, PAGE_SIZE, &buffer, NULL) != VMI_SUCCESS)
        {
            goto error_exit;
        }

        if (vmi_slat_change_gfn(vmi, view_x, shadow_page.read_write, shadow_page.execute) != VMI_SUCCESS)
        {
            goto error_exit;
        }

        printf("########### fast switch successfully enabled ########### \n");
    }

    if (vmi_resume_vm(vmi) ==  VMI_FAILURE)
        goto error_exit;
    
    status_t status = VMI_FAILURE;
    

    printf("Init done, waiting for events\n");

    time_t start_time,end_time;
    time (&start_time);
    time (&end_time);
    while (!interrupted && (difftime(end_time, start_time) < target_seconds)) 
    {
        time (&end_time);
        status = vmi_events_listen(vmi, 500);
        if (status == VMI_FAILURE)
            printf("Failed to listen on events\n");
    }
    printf("Ending run\n");

    printf("Target breakpoint hit. Count: %"PRIu64"\n", interrupt_struct.hit_count);
    printf("Wrong CR3 breakpoint hit. Count: %"PRIu64"\n", wrong_cr3_breakpoint_hits);

    retcode = 0;


error_exit:
    restore_original_value(vmi);

    if(use_cr3_guard)
    {
        vmi_clear_event(vmi, &cr3_event, NULL);
        vmi_clear_event(vmi, &int_event, NULL);
        vmi_clear_event(vmi, &sstep_event, NULL);
    }
    else
    {
        for (uint i = 0; i < vmi_get_num_vcpus(vmi); i++)
        {
            xc_altp2m_remove_fast_switch(xc, vm_id, i, targetCr3);
        }

        vmi_slat_destroy(vmi, view_rw);
        vmi_slat_destroy(vmi, view_x);
    }
    
    // close xen access handle if open.
    if(xc != NULL)
    {
        xc_interface_close(xc);
    }

    vmi_resume_vm(vmi);

    /* cleanup any memory associated with the LibVMI instance */
    vmi_destroy(vmi);

    if (init_data) 
    {
        free(init_data->entry[0].data);
        free(init_data);
    }

    return retcode;
}
