/**
 * VMI Event Based Prototype Approach Application
 **/
/////////////////////
// Includes
/////////////////////
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <inttypes.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <Python.h>

#include <libvmi/libvmi.h> 
#include <libvmi/events.h>

#include "prototype-deque.h"
#include "prototype-event-list.h"
#include "prototype-hawk.h"

#include <atomic>

using namespace std;
  
/////////////////////
// Defines
/////////////////////
#define UNUSED_PARAMETER(expr) (void)(expr);
//#define MYDEBUG
//#define printf(fmt, ...) (void)(0)

#define PAUSE_VM 0

// Event Names Contants
#define INTERRUPTED_EVENT 0
#define CR3_EVENT 1
#define SYSENTER_CS_EVENT 2

#define INT3_EVENT 32

/////////////////////
// Global Variables
/////////////////////
Deque<int> event_deque;
struct vmi_event_node *vmi_event_head;

// Result Measurements
//#define ASYNC_REGISTER_EVENTS
#define MONITORING_MODE
//#define ANALYSIS_MODE
//#define RE_REGISTER_EVENTS

#define MEASURE_EVENT_CALLBACK_TIME
#define ALWAYS_SEND_EVENT /* Always send event due to register multiple event on same page failure */

// Which events to monitor
// #define MONITOR_REGISTERS_EVENTS
#define MONITOR_INTERRUPTS_EVENTS

// Prototype Approaches
#define REGISTERS_APPROACH
#define FILTERING_APPROACH
#define INTTERUPTS_APPROACH
#define SYSCALLS_APPROACH

// Result variables
long irrelevant_events_count = 0;
long monitored_events_count = 0;

/////////////////////
// Static Functions
/////////////////////
static atomic<bool> interrupted(false);
static void close_handler(int sig)
{
    UNUSED_PARAMETER(sig); 
    interrupted = true;
    event_deque.push_front(INTERRUPTED_EVENT);
}

int main(int argc, char **argv)
{
    clock_t program_time = clock();
    printf("Prototype Event Hawk Program Initiated!\n");

    if(argc != 2)
    {
        fprintf(stderr, "Usage: prototype-hawk <Guest VM Name> \n");
        printf("Prototype Event Hawk-Eye Program Ended!\n");
        return 1; 
    }

    // Initialise variables
    vmi_instance_t vmi;

    // Setup signal action handling
    struct sigaction act;
    act.sa_handler = close_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT,  &act, NULL);
    sigaction(SIGALRM, &act, NULL);

    char *vm_name = argv[1];
    
    // Initialize the libvmi library.
    if (VMI_FAILURE ==
        vmi_init_complete(&vmi, vm_name, VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS, NULL, VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL))
    {
        printf("Failed to init LibVMI library.\n");
        return 2;
    }
    printf("LibVMI initialise succeeded: %p\n", vmi);

    #ifdef MONITORING_MODE    
        // Start security checking thread
        pthread_t sec_thread;
        if (pthread_create(&sec_thread, NULL, security_checking_thread, (void *)vmi) != 0)
            printf("Failed to create thread");
    #endif

    if(PAUSE_VM == 1) 
    {
        // Pause vm for consistent memory access
        if (VMI_SUCCESS != vmi_pause_vm(vmi))
        {
            printf("Failed to pause VM\n");
            cleanup(vmi);
            return 3;
        }
    }
    
    #ifdef MONITOR_REGISTERS_EVENTS
        // Register Processes Events
        if (register_registers_events(vmi) == false)
        {
            printf("Registering of registers events failed!\n");

            cleanup(vmi);
            printf("Prototype Event Hawk-Eye Program Ended!\n");
            return 4;
        }
    #endif

    #ifdef MONITOR_INTERRUPTS_EVENTS
        // Register Interrupts Events
        if (register_interrupts_events(vmi) == false)
        {
            printf("Registering of interrupts events failed!\n");

            cleanup(vmi);
            printf("Prototype Event Hawk-Eye Program Ended!\n");
            return 4;
        }
    #endif

    printf("Waiting for events...\n");
    while (!interrupted)
    {
         if (vmi_events_listen(vmi, 500) != VMI_SUCCESS) {
            printf("Error waiting for events, quitting...\n");
            interrupted = -1;
        }
    }

    cleanup(vmi);

    printf("Prototype Event Hawk-Eye Program Ended!\n");
    program_time = clock() - program_time;
    printf("Execution time: %f seconds\n", ((double)program_time)/CLOCKS_PER_SEC);
    return 0;
}

/////////////////////
// Definitions
/////////////////////
event_response_t mem_write_cb(vmi_instance_t vmi, vmi_event_t *event) 
{ 
    #ifdef MEASURE_EVENT_CALLBACK_TIME
        clock_t t;
        t = clock();
    #endif

    #ifdef ALWAYS_SEND_EVENT
        monitored_events_count++;
        vmi_clear_event(vmi, event, NULL);

        #ifdef MONITORING_MODE
            struct event_data *any_data = (struct event_data *) event->data;
            event_deque.push_back(any_data->type);
        #endif

        vmi_step_event(vmi, event, event->vcpu_id, 1, NULL);

        #ifdef MEASURE_EVENT_CALLBACK_TIME
            t = clock() - t;
            printf("mem_write_cb() took %f seconds to execute \n", ((double)t)/CLOCKS_PER_SEC);
        #endif

        return VMI_EVENT_RESPONSE_NONE;
    #endif

    // Always clear event on callback
    vmi_clear_event(vmi, event, NULL);

    monitored_events_count++;

    struct event_data *data = (struct event_data *) event->data;
    
    // Check that adddress hit is within monitoring range    
    addr_t event_addr = (event->mem_event.gfn << 12) + event->mem_event.offset;
    addr_t min_addr = data->physical_addr;
    addr_t max_addr = data->physical_addr + data->monitor_size;

    if (event_addr < min_addr || event_addr > max_addr)
    {
        irrelevant_events_count++;

        vmi_step_event(vmi, event, event->vcpu_id, 1, NULL);
        return VMI_EVENT_RESPONSE_NONE;
    }

    // print_mem_event(event);

    #ifdef MONITORING_MODE
        event_deque.push_back(data->type);
    #endif

    vmi_step_event(vmi, event, event->vcpu_id, 1, NULL);

    #ifdef MEASURE_EVENT_CALLBACK_TIME
        t = clock() - t;
        printf("mem_write_cb() took %f seconds to execute \n", ((double)t)/CLOCKS_PER_SEC);
    #endif

    return VMI_EVENT_RESPONSE_NONE;
} 

event_response_t reg_write_cb(vmi_instance_t vmi, vmi_event_t *event) 
{ 
    #ifdef MEASURE_EVENT_CALLBACK_TIME
        clock_t t;
        t = clock();
    #endif

    monitored_events_count++;
    vmi_clear_event(vmi, event, NULL);

    #ifdef MONITORING_MODE
        struct event_data *any_data = (struct event_data *) event->data;
        event_deque.push_back(any_data->type);
    #endif

    print_reg_event(event);

    vmi_step_event(vmi, event, event->vcpu_id, 1, NULL);

    #ifdef MEASURE_EVENT_CALLBACK_TIME
        t = clock() - t;
        printf("reg_write_cb() took %f seconds to execute \n", ((double)t)/CLOCKS_PER_SEC);
    #endif

    return VMI_EVENT_RESPONSE_NONE;
} 

event_response_t int_write_cb(vmi_instance_t vmi, vmi_event_t *event) 
{ 
    #ifdef MEASURE_EVENT_CALLBACK_TIME
        clock_t t;
        t = clock();
    #endif

    monitored_events_count++;
    vmi_clear_event(vmi, event, NULL);

    #ifdef MONITORING_MODE
        struct event_data *any_data = (struct event_data *) event->data;
        event_deque.push_back(any_data->type);
    #endif

    print_int_event(event);

    vmi_step_event(vmi, event, event->vcpu_id, 1, NULL);

    #ifdef MEASURE_EVENT_CALLBACK_TIME
        t = clock() - t;
        printf("int_write_cb() took %f seconds to execute \n", ((double)t)/CLOCKS_PER_SEC);
    #endif

    return VMI_EVENT_RESPONSE_NONE;
} 

void free_event_data(vmi_event_t *event, status_t rc)
{
    struct event_data * data = (struct event_data *) event->data;
    printf("Freeing data for event type: %lu due to status %d \n", data->type, rc);
    free(data); 
}

bool register_registers_events(vmi_instance_t vmi)
{
    //printf("Registering Registers Events\n");

    // Register CR3 register
    printf("Registering CR3 register event\n");
    
    vmi_event_t *cr3_event = (vmi_event_t *) malloc(sizeof(vmi_event_t));
    SETUP_REG_EVENT(cr3_event, CR3, VMI_REGACCESS_W, 0, reg_write_cb);

    #ifdef ASYNC_REGISTER_EVENTS
        cr3_event.reg_event.async = 1;
    #endif

    // Setup event context data
    struct event_data *cr3_event_data = (struct event_data *) malloc(sizeof(struct event_data));
    cr3_event_data->type = CR3_EVENT;

    cr3_event->data = cr3_event_data;

    if (vmi_register_event(vmi, cr3_event) == VMI_FAILURE)
        printf("Failed to register CR3 register event!\n");
    else
        push_vmi_event(&vmi_event_head, cr3_event);

    // Register sysenter_cs register
    vmi_event_t *sysenter_cs_event = (vmi_event_t *) malloc(sizeof(vmi_event_t));
    SETUP_REG_EVENT(sysenter_cs_event, SYSENTER_CS, VMI_REGACCESS_W, 0, reg_write_cb);

    // Setup event context data
    struct event_data *sysenter_cs_event_data = (struct event_data *) malloc(sizeof(struct event_data));
    sysenter_cs_event_data->type = SYSENTER_CS_EVENT;

    sysenter_cs_event->data = sysenter_cs_event_data;

    if (vmi_register_event(vmi, sysenter_cs_event) == VMI_FAILURE)
        printf("Failed to register sysenter_cs register event!\n");
    else
        push_vmi_event(&vmi_event_head, sysenter_cs_event);


    return true;
}

bool register_interrupts_events(vmi_instance_t vmi)
{
    // Register INT3 interrupt
    printf("Registering INT3 interrupt event\n");
    
    vmi_event_t *int3_event = (vmi_event_t *) malloc(sizeof(vmi_event_t));
    SETUP_INTERRUPT_EVENT(int3_event, 1, int_write_cb);
    
    int3_event->interrupt_event.intr = INT3;

    // Setup event context data
    struct event_data *int3_event_data = (struct event_data *) malloc(sizeof(struct event_data));
    int3_event_data->type = INT3_EVENT;

    int3_event->data = int3_event_data;

    if (vmi_register_event(vmi, int3_event) == VMI_FAILURE)
        printf("Failed to register INT3 interrupt event!\n");
    else
        push_vmi_event(&vmi_event_head, int3_event);

    return true;
}

void cleanup(vmi_instance_t vmi)
{
    // Send Interrupt event to security checking thread
    interrupted = true;
    event_deque.push_front(INTERRUPTED_EVENT);

    if(PAUSE_VM == 1) 
        vmi_resume_vm(vmi);

    struct vmi_event_node *current = vmi_event_head;
    struct vmi_event_node *next = vmi_event_head;

    while (current) 
    {
        next = current->next;

        vmi_clear_event(vmi, current->event, free_event_data);

        free(current);
        current = next;
    }

    // Perform cleanup of libvmi instance
    vmi_destroy(vmi);

    // Print Statistics
    if (monitored_events_count != 0) 
    {
        printf("Total Irrelevant Events: %ld\n", irrelevant_events_count);
        printf("Total Hit Events: %ld\n", (monitored_events_count - irrelevant_events_count));
        printf("Total Monitored Events: %ld\n", monitored_events_count);
        printf("Total Irrelevant Events Percentage: %f%%\n", (double) irrelevant_events_count / (double)monitored_events_count * 100);
        printf("Total Hit Events: %f%%\n", (1 - (double) irrelevant_events_count / (double)monitored_events_count) * 100);
    }
}

void print_mem_event(vmi_event_t *event)
{
    printf("PAGE ACCESS: %c%c%c for GFN %" PRIx64" (offset %06" PRIx64") gla %016" PRIx64" (vcpu %" PRIu32")\n",
        (event->mem_event.out_access & VMI_MEMACCESS_R) ? 'r' : '-',
        (event->mem_event.out_access & VMI_MEMACCESS_W) ? 'w' : '-',
        (event->mem_event.out_access & VMI_MEMACCESS_X) ? 'x' : '-',
        event->mem_event.gfn,
        event->mem_event.offset,
        event->mem_event.gla,
        event->vcpu_id
    );
}

void print_reg_event(vmi_event_t *event)
{
    printf("REG ACCESS: %c%c for value %" PRIx64" (vcpu %" PRIu32")\n",
        (event->reg_event.out_access & VMI_REGACCESS_R) ? 'r' : '-',
        (event->reg_event.out_access & VMI_REGACCESS_W) ? 'w' : '-',
        event->reg_event.value,
        event->vcpu_id
    );
}

void print_int_event(vmi_event_t *event)
{
    printf("INTERRUPT EVENT for GFN %" PRIx64" (offset %06" PRIx64") gla %016" PRIx64" (vcpu %" PRIu32")\n",
        event->interrupt_event.gfn,
        event->interrupt_event.offset,
        event->interrupt_event.gla,
        event->vcpu_id
    );
}

void *security_checking_thread(void *arg)
{
    vmi_instance_t vmi = (vmi_instance_t)arg;
    printf("Security Checking Thread Initated: %p\n", vmi);

    // Py_Initialize();
    // PyRun_SimpleString("from time import time,ctime\n"
    //                    "print 'Today is',ctime(time())\n");
    int res = 0;
    UNUSED_PARAMETER(res);

    int event_type = INTERRUPTED_EVENT;
    while(!interrupted)
    {
        event_type = event_deque.pop();

        switch (event_type)
        {
            case CR3_EVENT:{
                printf("Encountered CR3_EVENT\n");
                /*#ifdef RE_REGISTER_EVENTS
                    // Recheck processes
                    register_registers_events(vmi);
                #endif*/

                /*#ifdef ANALYSIS_MODE
                    // Volatility Plugin linux_check_fop
                    res = system("python scripts/check_fop.py");
                    // Volatility Plugin linux_check_creds
                    res = system("python scripts/check_creds.py");
                #endif*/
                break;
            } 
            case SYSENTER_CS_EVENT:{
                printf("Encountered SYSENTER_CS_EVENT\n");
                break;
            } 
            case INT3_EVENT:{
                printf("Encountered INT3_EVENT\n");
                break;
            }
            case INTERRUPTED_EVENT:
            {
                printf("Encountered INTERRUPTED_EVENT\n");
                printf("Security Checking Thread Ended!\n"); 
                // Py_Finalize();
                return NULL;
            }
            default:
            {
                printf("Unknown event: %d encountered\n", event_type);
                break;
            }
        }
    }
    
    printf("Security Checking Thread Ended!\n");
    // Py_Finalize();
    return NULL;
}