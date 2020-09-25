/**
 * @file
 * @author Philippe Antoine <contact@catenacyber.fr>
 * fuzz target for AppLayerProtoDetectGetProto
 */


#include "suricata-common.h"
#include "app-layer-detect-proto.h"
#include "flow-util.h"
#include "app-layer-parser.h"
#include "util-unittest-helper.h"
#include "util-byte.h"
#include "stream-tcp-reassemble.h"
#include "stream-tcp.h"
#include "ippair.h"
#include "app-layer.h"

#define HEADER_LEN 6

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

AppLayerParserThreadCtx *alp_tctx = NULL;

static int StreamTcpUTAddSegmentWithPayload(ThreadVars *tv, TcpReassemblyThreadCtx *ra_ctx, TcpStream *stream, uint32_t seq, uint8_t *payload, uint16_t len)
{
    TcpSegment *s = StreamTcpGetSegment(tv, ra_ctx);
    if (s == NULL) {
        abort();
    }
    
    s->seq = seq;
    TCP_SEG_LEN(s) = len;
    
    Packet *p = UTHBuildPacketReal(payload, len, IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1234, 80);
    if (p == NULL) {
        abort();
    }
    p->tcph->th_seq = htonl(seq);
    
    if (StreamTcpReassembleInsertSegment(tv, ra_ctx, stream, s, p, TCP_GET_SEQ(p), p->payload, p->payload_len) < 0) {
        return -1;
    }
    
    SCFree(p);
    return 0;
}

static void StreamTcpUTSetupStream(TcpStream *s, uint32_t isn)
{
    memset(s, 0x00, sizeof(TcpStream));
    
    s->isn = isn;
    STREAMTCP_SET_RA_BASE_SEQ(s, isn);
    s->base_seq = isn+1;
}

/* input buffer is structured this way :
 * 6 bytes header,
 * then sequence of buffers separated by magic bytes 01 D5 CA 7A */

/* The 6 bytes header is
 * alproto
 * proto
 * source port (uint16_t)
 * destination port (uint16_t) */

const uint8_t separator[] = {0x01, 0xD5, 0xCA, 0x7A};
SCInstance surifuzz;
uint64_t forceLayer = 0;
TcpReassemblyThreadCtx *ra_ctx = NULL;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    Flow * f;
    TcpSession ssn;
    const uint8_t * albuffer;
    uint8_t * alnext;
    size_t alsize;
    // used to find under and overflows
    // otherwise overflows do not fail as they read the next packet
    uint8_t * isolatedBuffer;

    if (size < HEADER_LEN) {
        return 0;
    }

    if (alp_tctx == NULL) {
        //Redirects logs to /dev/null
        setenv("SC_LOG_OP_IFACE", "file", 0);
        setenv("SC_LOG_FILE", "/dev/null", 0);

        InitGlobal();
        run_mode = RUNMODE_PCAP_FILE;
        GlobalsInitPreConfig();

        //redirect logs to /tmp
        ConfigSetLogDirectory("/tmp/");

        PostConfLoadedSetup(&surifuzz);
        alp_tctx = AppLayerParserThreadCtxAlloc();
        const char* forceLayerStr = getenv("FUZZ_APPLAYER");
        if (forceLayerStr) {
            if (ByteExtractStringUint64(&forceLayer, 10, 0, forceLayerStr) < 0) {
                forceLayer = 0;
                printf("Invalid numeric value for FUZZ_APPLAYER environment variable");
            }
        }
        PreRunPostPrivsDropInit(run_mode);
        PostConfLoadedDetectSetup(&surifuzz);
        ra_ctx = StreamTcpReassembleInitThreadCtx(NULL);
    }

    if (data[0] >= ALPROTO_MAX) {
        return 0;
    }
    //no UTHBuildFlow to have storage
    f = FlowAlloc();
    if (f == NULL) {
        return 0;
    }
    f->flags |= FLOW_IPV4;
    f->src.addr_data32[0] = 0x01020304;
    f->dst.addr_data32[0] = 0x05060708;
    f->sp = 1234;
    f->dp = 80;
    f->proto = IPPROTO_TCP;
    memset(&ssn, 0, sizeof(TcpSession));
    f->protoctx = &ssn;
    f->protomap = FlowGetProtoMapping(f->proto);
    if (forceLayer > 0) {
        f->alproto = forceLayer;
    } else {
        f->alproto = ALPROTO_HTTP;
    }

    Packet *p = PacketGetFromAlloc();
    p->proto = IPPROTO_TCP;
    p->flow = f;

    ThreadVars tv;
    memset(&tv, 0x00, sizeof(tv));

    stream_config.flags |= STREAMTCP_INIT_FLAG_INLINE;
    ssn.data_first_seen_dir = APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER;

    StreamTcpUTSetupStream(&ssn.server, 1);
    StreamTcpUTSetupStream(&ssn.client, 1);
    StreamingBuffer x = STREAMING_BUFFER_INITIALIZER(&stream_config.sbcnf);
    StreamingBuffer y = STREAMING_BUFFER_INITIALIZER(&stream_config.sbcnf);
    ssn.client.sb = x;
    ssn.server.sb = y;

    uint8_t c2si[] = "CONNECT abc:443 HTTP/1.1\r\nUser-Agent: Victor/1.0\r\n\r\n";
    uint8_t s2ci[] = "HTTP/1.1 200 OK\r\nServer: VictorServer/1.0\r\n\r\n";
    uint32_t seqcli = 2;
    uint32_t seqsrv = 2;

    if (StreamTcpUTAddSegmentWithPayload(&tv, ra_ctx, &ssn.client, seqcli, c2si, sizeof(c2si) - 1) == -1) {
        abort();
    }
    seqcli += sizeof(c2si) - 1;
    if(StreamTcpReassembleAppLayer(&tv, ra_ctx, &ssn,  &ssn.client, p, UPDATE_DIR_PACKET) < 0) {
        abort();
    }
    if(StreamTcpUTAddSegmentWithPayload(&tv, ra_ctx,  &ssn.server, seqsrv, s2ci, sizeof(s2ci) - 1) == -1) {
        abort();
    }
    seqsrv += sizeof(s2ci) - 1;
    if(StreamTcpReassembleAppLayer(&tv, ra_ctx, &ssn, &ssn.server, p, UPDATE_DIR_PACKET) < 0) {
        abort();
    }

    /*
     * We want to fuzz multiple calls to AppLayerParserParse
     * because some parts of the code are only reached after
     * multiple packets (in SMTP for example).
     * So we treat our input as a list of buffers with magic separator.
     */
    albuffer = data + HEADER_LEN;
    alsize = size - HEADER_LEN;
    uint8_t flags = STREAM_START;
    int flip = 0;
    alnext = memmem(albuffer, alsize, separator, 4);
    while (alnext) {
        if (flip) {
            flags |= STREAM_TOCLIENT;
            flags &= ~(STREAM_TOSERVER);
            flip = 0;
        } else {
            flags |= STREAM_TOSERVER;
            flags &= ~(STREAM_TOCLIENT);
            flip = 1;
        }

        if (alnext != albuffer) {
            // only if we have some data
            isolatedBuffer = malloc(alnext - albuffer);
            if (isolatedBuffer == NULL) {
                return 0;
            }
            memcpy(isolatedBuffer, albuffer, alnext - albuffer);
            if (flags & STREAM_TOSERVER) {
                if (StreamTcpUTAddSegmentWithPayload(&tv, ra_ctx, &ssn.server, seqsrv, isolatedBuffer, alnext - albuffer) == -1) {
                    return 0;
                }
                seqsrv += alnext - albuffer;
                if(StreamTcpReassembleAppLayer(&tv, ra_ctx, &ssn,  &ssn.server, p, UPDATE_DIR_PACKET) < 0) {
                    return 0;
                }
            } else {
                if(StreamTcpUTAddSegmentWithPayload(&tv, ra_ctx,  &ssn.client, seqcli, isolatedBuffer, alnext - albuffer) == -1) {
                    return 0;
                }
                seqcli += alnext - albuffer;
                if(StreamTcpReassembleAppLayer(&tv, ra_ctx, &ssn, &ssn.client, p, UPDATE_DIR_PACKET) < 0) {
                    return 0;
                }
            }
            free(isolatedBuffer);
            flags &= ~(STREAM_START);
            if (f->alparser &&
                   (((flags & STREAM_TOSERVER) != 0 &&
                     AppLayerParserStateIssetFlag(f->alparser, APP_LAYER_PARSER_EOF_TS)) ||
                    ((flags & STREAM_TOCLIENT) != 0 &&
                     AppLayerParserStateIssetFlag(f->alparser, APP_LAYER_PARSER_EOF_TC)))) {
                //no final chunk
                alsize = 0;
                break;
            }
        }
        alsize -= alnext - albuffer + 4;
        albuffer = alnext + 4;
        if (alsize == 0) {
            break;
        }
        alnext = memmem(albuffer, alsize, separator, 4);
    }
    if (alsize > 0 ) {
        if (flip) {
            flags |= STREAM_TOCLIENT;
            flags &= ~(STREAM_TOSERVER);
            flip = 0;
        } else {
            flags |= STREAM_TOSERVER;
            flags &= ~(STREAM_TOCLIENT);
            flip = 1;
        }
        flags |= STREAM_EOF;
        isolatedBuffer = malloc(alsize);
        if (isolatedBuffer == NULL) {
            return 0;
        }
        memcpy(isolatedBuffer, albuffer, alsize);
        if (flags & STREAM_TOSERVER) {
            if (StreamTcpUTAddSegmentWithPayload(&tv, ra_ctx, &ssn.server, seqsrv, isolatedBuffer, alsize) == -1) {
                return 0;
            }
            seqsrv += alsize;
            if(StreamTcpReassembleAppLayer(&tv, ra_ctx, &ssn,  &ssn.server, p, UPDATE_DIR_PACKET) < 0) {
                return 0;
            }
        } else {
            if(StreamTcpUTAddSegmentWithPayload(&tv, ra_ctx,  &ssn.client, seqcli, isolatedBuffer, alsize) == -1) {
                return 0;
            }
            seqcli += alsize;
            if(StreamTcpReassembleAppLayer(&tv, ra_ctx, &ssn, &ssn.client, p, UPDATE_DIR_PACKET) < 0) {
                return 0;
            }
        }
        free(isolatedBuffer);
    }

    FlowFree(f);
    SCFree(p);
    StreamTcpReturnStreamSegments(&ssn.client);
    StreamTcpReturnStreamSegments(&ssn.server);
    StreamingBufferClear(&ssn.client.sb);
    StreamingBufferClear(&ssn.server.sb);
    return 0;
}
