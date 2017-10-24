#ifndef PROTOTYPE_HAWK
#define PROTOTYPE_HAWK

/////////////////////
// Structs
/////////////////////

struct event_data 
{
    // Event type
    unsigned long type;

    // Physical address of event to monitor
    unsigned long physical_addr;

    // Size of monitoring page
    unsigned long monitor_size;
};

///////////////////// 
// Functions
/////////////////////

void cleanup(vmi_instance_t vmi);

event_response_t mem_write_cb(vmi_instance_t vmi, vmi_event_t *event);
event_response_t reg_write_cb(vmi_instance_t vmi, vmi_event_t *event);
event_response_t int_write_cb(vmi_instance_t vmi, vmi_event_t *event);

void free_event_data(vmi_event_t *event, status_t rc);

void print_mem_event(vmi_event_t *event);
void print_reg_event(vmi_event_t *event);
void print_int_event(vmi_event_t *event);

bool register_registers_events(vmi_instance_t vmi);
bool register_interrupts_events(vmi_instance_t vmi);

void *security_checking_thread(void *arg);

#endif