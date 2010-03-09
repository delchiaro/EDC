static void     Usage( char *progname );
static char     *knx_physical( uint16_t phy_addr );
static char     *knx_group( uint16_t grp_addr );

/*
 * EIB request frame
 */
typedef struct __attribute__((packed)) {
        uint8_t  code;
        uint8_t  zero;
        uint8_t  ctrl;
        uint8_t  ntwrk;
        uint16_t saddr;
        uint16_t daddr;
        uint8_t  length;
        uint8_t  tpci;
        uint8_t  apci;
        uint8_t  data[16];
} CEMIFRAME;
