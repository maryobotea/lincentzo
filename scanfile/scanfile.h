#include "../antiviRus/antiviRus.h"
#include "../database/database.h"
#include "../workqueue/workqueue.h"

enum flags {
    ANOMALY_NONE              = 0,
    ANOMALY_RWE               = 1 << 0,  // 0x01
    ANOMALY_INFLATION         = 1 << 1,  // 0x02
    ANOMALY_EP_IN_CAVE        = 1 << 2,  // 0x04
    ANOMALY_HIGH_ENTROPY      = 1 << 3,  // 0x08
    ANOMALY_INST_CAV          = 1 << 4,  // 0x10
    ANOMALY_JUMP              = 1 << 5,  // 0x20
    ANOMALY_SUSP_NAME         = 1 << 6,  // 0x40
    ANOMALY_HIDDEN_D_DISC     = 1 << 7,  // 0x80
    ANOMALY_HIDDEN_D_RAM      = 1 << 8,   // 0x100
    ANOMALY_EMPTY_SEC         = 1 << 9,   // 0x200
    ANOMALY_EP_IN_0_SEC       = 1 << 10,  // 0x400
    ANOMALY_EP_OUTSIDE        = 1 << 11,   // 0x800
    ANOMALY_SEC_BEYOND_EOF    = 1 << 12,  // 0x1000
    ANOMALY_UNALIGNED_SEC     = 1 << 13,  // 0x2000
    ANOMALY_SEC_OVERLAP       = 1 << 14,  // 0x4000
    ANOMALY_MULTI_EXEC        = 1 << 15,   // 0x8000
    ANOMALY_EP_IN_NONEXEC_SEC = 1 << 16,   // 0x10000
    ANOMALY_SEC_IN_HEADER     = 1 << 17,   // 0x20000
    ANOMALY_TRAILING_DOTS     = 1 << 18,   // 0x40000
    ANOMALY_EP_IN_OVERLAY     = 1 << 19,   // 0x80000
    ANOMALY_EMBEDDED_PE       = 1 << 20,   // 0x100000
    ANOMALY_ENTR_OVERLAY      = 1 << 21,   // 0x200000
    ANOMALY_NOP_SLED          = 1 << 22,   // 0x400000
};

typedef enum flags AnomalyFlags;

struct report {
    AnomalyFlags  flags;    
    int32         totalScore;
    double        maxEntropy;
};

typedef struct report ScanReport;

double calculate_entropy(int8*, int32);

int32 scanfile(Database *, Workqueue *, int32, int8 *);
