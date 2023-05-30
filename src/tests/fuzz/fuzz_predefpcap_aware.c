/**
 * @file
 * @author Philippe Antoine <contact@catenacyber.fr>
 * fuzz target for predefined signatures and pcap (aware)
 */

#include "suricata-common.h"
#include "source-pcap-file.h"
#include "detect-engine.h"
#include "util-classification-config.h"
#include "util-reference-config.h"
#include "app-layer.h"
#include "tm-queuehandlers.h"
#include "util-cidr.h"
#include "util-profiling.h"
#include "util-proto-name.h"
#include "detect-engine-tag.h"
#include "detect-engine-threshold.h"
#include "host-bit.h"
#include "ippair-bit.h"
#include "app-layer-htp.h"
#include "detect-fast-pattern.h"
#include "util-unittest-helper.h"
#include "conf-yaml-loader.h"
#include "pkt-var.h"
#include "flow-util.h"
#include "tm-modules.h"
#include "tmqh-packetpool.h"
#include "util-conf.h"
#include "packet.h"

#include <fuzz_pcap.h>

int LLVMFuzzerInitialize(const int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t size, size_t MaxSize, unsigned int Seed);
size_t LLVMFuzzerMutate(uint8_t *Data, size_t size, size_t MaxSize);
char *debug = NULL;

static int initialized = 0;
ThreadVars tv;
DecodeThreadVars *dtv;
// FlowWorkerThreadData
void *fwd;
SCInstance surifuzz;
SC_ATOMIC_EXTERN(unsigned int, engine_stage);

#include "confyaml.c"

char *filepath = NULL;

int LLVMFuzzerInitialize(const int *argc, char ***argv)
{
    filepath = dirname(strdup((*argv)[0]));
    debug = getenv("FUZZ_DEBUG");
    return 0;
}

size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t size, size_t MaxSize, unsigned int Seed)
{
    if ((Seed & 1) == 0) {
        return LLVMFuzzerMutate(Data, size, MaxSize); // qsize
    }
    uint32_t crc = Seed >> 1;
    uint8_t pattern_repeat_len = 1 + (crc & 0xFF);
    uint32_t pattern_repeat_nb = 512 * (((crc >> 8) & 0xFF) + 1);
    uint16_t prefix_postfix_ratio = (crc >> 16);

    if (pattern_repeat_len > size) {
        pattern_repeat_len = (uint8_t)size;
    }
    size_t prefix_postfix_len = size - pattern_repeat_len;
    size_t prefix_len = (prefix_postfix_len * prefix_postfix_ratio) / 0xFFFF;
    size_t postfix_len = prefix_postfix_len - prefix_len;
    size_t qsize = prefix_len + (pattern_repeat_nb * pattern_repeat_len) + postfix_len;
    if (qsize > MaxSize) {
        pattern_repeat_nb -= 1 + (qsize - MaxSize) / pattern_repeat_len;
        qsize = prefix_len + (pattern_repeat_nb * pattern_repeat_len) + postfix_len;
    }
    if (debug) {
        printf("size = %zu\n", size);
        printf("MaxSize = %zu\n", MaxSize);
        printf("Seed = %u\n", Seed);
        printf("pattern_repeat_len = %hhu\n", pattern_repeat_len);
        printf("pattern_repeat_nb = %u\n", pattern_repeat_nb);
        printf("prefix_postfix_ratio = %hu\n", prefix_postfix_ratio);
        printf("prefix_postfix_len = %zu\n", prefix_postfix_len);
        printf("prefix_len = %zu\n", prefix_len);
        printf("postfix_len = %zu\n", postfix_len);
        printf("qsize = %zu\n", qsize);
    }
    if (MaxSize < qsize) {
        printf("small %zx vs %zx\n", MaxSize, qsize);
        return size;
    }
    uint8_t *qdata = malloc(qsize);
    memcpy(qdata, Data, prefix_len);
    for (size_t i = 0; i < pattern_repeat_nb; i++) {
        memcpy(qdata + prefix_len + i * pattern_repeat_len, Data + prefix_len, pattern_repeat_len);
    }
    memcpy(qdata + qsize - postfix_len, Data + size - postfix_len, postfix_len);
    memcpy(Data, qdata, qsize);
    free(qdata);
    return qsize;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FPC_buffer_t pkts;
    const u_char *pkt;
    struct pcap_pkthdr header;
    int r;
    Packet *p;
    size_t pcap_cnt = 0;

    if (initialized == 0) {
        // Redirects logs to /dev/null
        setenv("SC_LOG_OP_IFACE", "file", 0);
        setenv("SC_LOG_FILE", "/dev/null", 0);

        InitGlobal();

        GlobalsInitPreConfig();
        run_mode = RUNMODE_PCAP_FILE;
        // redirect logs to /tmp
        ConfigSetLogDirectory("/tmp/");
        // disables checksums validation for fuzzing
        if (ConfYamlLoadString(configNoChecksum, strlen(configNoChecksum)) != 0) {
            abort();
        }
        surifuzz.sig_file = malloc(strlen(filepath) + strlen("/fuzz.rules") + 1);
        memcpy(surifuzz.sig_file, filepath, strlen(filepath));
        memcpy(surifuzz.sig_file + strlen(filepath), "/fuzz.rules", strlen("/fuzz.rules"));
        surifuzz.sig_file[strlen(filepath) + strlen("/fuzz.rules")] = 0;
        surifuzz.sig_file_exclusive = 1;
        // loads rules after init
        surifuzz.delayed_detect = 1;

        PostConfLoadedSetup(&surifuzz);
        PreRunPostPrivsDropInit(run_mode);
        PostConfLoadedDetectSetup(&surifuzz);

        memset(&tv, 0, sizeof(tv));
        tv.flow_queue = FlowQueueNew();
        if (tv.flow_queue == NULL)
            abort();
        dtv = DecodeThreadVarsAlloc(&tv);
        DecodeRegisterPerfCounters(dtv, &tv);
        tmm_modules[TMM_FLOWWORKER].ThreadInit(&tv, NULL, &fwd);
        StatsSetupPrivate(&tv);

        extern uint16_t max_pending_packets;
        max_pending_packets = 128;
        PacketPoolInit();
        if (DetectEngineReload(&surifuzz) < 0) {
            return 0;
        }

        SC_ATOMIC_SET(engine_stage, SURICATA_RUNTIME);
        initialized = 1;
    }

    if (size < FPC0_HEADER_LEN) {
        return 0;
    }
    // initialize FPC with the buffer
    if (FPC_init(&pkts, data, size) < 0) {
        return 0;
    }

    // loop over packets
    r = FPC_next(&pkts, &header, &pkt);
    p = PacketGetFromAlloc();
    if (p == NULL || r <= 0 || header.ts.tv_sec >= INT_MAX - 3600) {
        goto bail;
    }
    p->ts = SCTIME_FROM_TIMEVAL(&header.ts);
    p->datalink = pkts.datalink;
    p->pkt_src = PKT_SRC_WIRE;
    while (r > 0) {
        if (PacketCopyData(p, pkt, header.caplen) == 0) {
            // DecodePcapFile
            TmEcode ecode = tmm_modules[TMM_DECODEPCAPFILE].Func(&tv, p, dtv);
            if (ecode == TM_ECODE_FAILED) {
                break;
            }
            Packet *extra_p = PacketDequeueNoLock(&tv.decode_pq);
            while (extra_p != NULL) {
                PacketFreeOrRelease(extra_p);
                extra_p = PacketDequeueNoLock(&tv.decode_pq);
            }
            tmm_modules[TMM_FLOWWORKER].Func(&tv, p, fwd);
            extra_p = PacketDequeueNoLock(&tv.decode_pq);
            while (extra_p != NULL) {
                PacketFreeOrRelease(extra_p);
                extra_p = PacketDequeueNoLock(&tv.decode_pq);
            }
        }
        r = FPC_next(&pkts, &header, &pkt);
        if (r <= 0 || header.ts.tv_sec >= INT_MAX - 3600) {
            goto bail;
        }
        PacketRecycle(p);
        p->ts = SCTIME_FROM_TIMEVAL(&header.ts);
        p->datalink = pkts.datalink;
        pcap_cnt++;
        p->pcap_cnt = pcap_cnt;
        p->pkt_src = PKT_SRC_WIRE;
    }
bail:
    if (p != NULL) {
        PacketFree(p);
    }
    FlowReset();

    return 0;
}
