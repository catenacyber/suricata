/* Copyright (C) 2007-2018 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \ingroup httplayer
 *
 * @{
 */


/**
 * \file
 *
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 *
 * Implements the http_cookie keyword
 */

#include "suricata-common.h"
#include "threads.h"
#include "decode.h"
#include "detect.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-buffer.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-content.h"
#include "detect-pcre.h"

#include "flow.h"
#include "flow-var.h"
#include "flow-util.h"

#include "util-debug.h"
#include "util-error.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-spm.h"
#include "util-print.h"

#include "app-layer.h"
#include "app-layer-parser.h"

#include "app-layer-htp.h"
#include "detect-http-cookie.h"
#include "stream-tcp.h"

static int DetectHttpCookieSetup (DetectEngineCtx *, Signature *, const char *);
static int DetectHttpCookieSetupSticky (DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectHttpCookieRegisterTests(void);
#endif
static int g_http_cookie_buffer_id = 0;

static bool GetRequestData(DetectEngineThreadCtx *det_ctx, const void *txv,
        const uint8_t _flow_flags, const uint8_t **buf, uint32_t *buf_len);
static bool GetResponseData(DetectEngineThreadCtx *det_ctx, const void *txv,
        const uint8_t _flow_flags, const uint8_t **buf, uint32_t *buf_len);
/**
 * \brief Registration function for keyword: http_cookie
 */
void DetectHttpCookieRegister(void)
{
    /* http_cookie content modifier */
    sigmatch_table[DETECT_HTTP_COOKIE_CM].name = "http_cookie";
    sigmatch_table[DETECT_HTTP_COOKIE_CM].desc =
            "content modifier to match only on the HTTP cookie-buffer";
    sigmatch_table[DETECT_HTTP_COOKIE_CM].url = "/rules/http-keywords.html#http-cookie";
    sigmatch_table[DETECT_HTTP_COOKIE_CM].Setup = DetectHttpCookieSetup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_HTTP_COOKIE_CM].RegisterTests = DetectHttpCookieRegisterTests;
#endif
    sigmatch_table[DETECT_HTTP_COOKIE_CM].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_HTTP_COOKIE_CM].flags |= SIGMATCH_INFO_CONTENT_MODIFIER;
    sigmatch_table[DETECT_HTTP_COOKIE_CM].alternative = DETECT_HTTP_COOKIE;

    /* http.cookie sticky buffer */
    sigmatch_table[DETECT_HTTP_COOKIE].name = "http.cookie";
    sigmatch_table[DETECT_HTTP_COOKIE].desc = "sticky buffer to match on the HTTP Cookie/Set-Cookie buffers";
    sigmatch_table[DETECT_HTTP_COOKIE].url = "/rules/http-keywords.html#http-cookie";
    sigmatch_table[DETECT_HTTP_COOKIE].Setup = DetectHttpCookieSetupSticky;
    sigmatch_table[DETECT_HTTP_COOKIE].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_HTTP_COOKIE].flags |= SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerInspectEngineRegister("http_cookie", ALPROTO_HTTP1, SIG_FLAG_TOSERVER,
            HTP_REQUEST_PROGRESS_HEADERS, DetectEngineInspectBufferGeneric, GetRequestData);
    DetectAppLayerInspectEngineRegister("http_cookie", ALPROTO_HTTP1, SIG_FLAG_TOCLIENT,
            HTP_REQUEST_PROGRESS_HEADERS, DetectEngineInspectBufferGeneric, GetResponseData);

    DetectAppLayerMpmRegister("http_cookie", SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            GetRequestData, ALPROTO_HTTP1, HTP_REQUEST_PROGRESS_HEADERS);
    DetectAppLayerMpmRegister("http_cookie", SIG_FLAG_TOCLIENT, 2, PrefilterGenericMpmRegister,
            GetResponseData, ALPROTO_HTTP1, HTP_REQUEST_PROGRESS_HEADERS);

    DetectAppLayerInspectEngineRegister("http_cookie", ALPROTO_HTTP2, SIG_FLAG_TOSERVER,
            HTTP2StateDataClient, DetectEngineInspectBufferGeneric, SCHttp2TxGetCookie);
    DetectAppLayerInspectEngineRegister("http_cookie", ALPROTO_HTTP2, SIG_FLAG_TOCLIENT,
            HTTP2StateDataServer, DetectEngineInspectBufferGeneric, SCHttp2TxGetCookie);

    DetectAppLayerMpmRegister("http_cookie", SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            SCHttp2TxGetCookie, ALPROTO_HTTP2, HTTP2StateDataClient);
    DetectAppLayerMpmRegister("http_cookie", SIG_FLAG_TOCLIENT, 2, PrefilterGenericMpmRegister,
            SCHttp2TxGetCookie, ALPROTO_HTTP2, HTTP2StateDataServer);

    DetectBufferTypeSetDescriptionByName("http_cookie",
            "http cookie header");

    g_http_cookie_buffer_id = DetectBufferTypeGetByName("http_cookie");
}

/**
 * \brief this function setups the http_cookie modifier keyword used in the rule
 *
 * \param de_ctx   Pointer to the Detection Engine Context
 * \param s        Pointer to the Signature to which the current keyword belongs
 * \param str      Should hold an empty string always
 *
 * \retval  0 On success
 * \retval -1 On failure
 */

static int DetectHttpCookieSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    return DetectEngineContentModifierBufferSetup(
            de_ctx, s, str, DETECT_HTTP_COOKIE_CM, g_http_cookie_buffer_id, ALPROTO_HTTP1);
}

/**
 * \brief this function setup the http.cookie keyword used in the rule
 *
 * \param de_ctx   Pointer to the Detection Engine Context
 * \param s        Pointer to the Signature to which the current keyword belongs
 * \param str      Should hold an empty string always
 *
 * \retval 0       On success
 */
static int DetectHttpCookieSetupSticky(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (SCDetectBufferSetActiveList(de_ctx, s, g_http_cookie_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_HTTP) < 0)
        return -1;

    return 0;
}

static bool GetRequestData(DetectEngineThreadCtx *det_ctx, const void *txv,
        const uint8_t _flow_flags, const uint8_t **data, uint32_t *data_len)
{
    htp_tx_t *tx = (htp_tx_t *)txv;

    if (htp_tx_request_headers(tx) == NULL)
        return false;

    const htp_header_t *h = htp_tx_request_header(tx, "Cookie");
    if (h == NULL || htp_header_value(h) == NULL) {
        SCLogDebug("HTTP cookie header not present in this request");
        return false;
    }

    *data_len = htp_header_value_len(h);
    *data = htp_header_value_ptr(h);
    return true;
}

static bool GetResponseData(DetectEngineThreadCtx *det_ctx, const void *txv,
        const uint8_t _flow_flags, const uint8_t **data, uint32_t *data_len)
{
    htp_tx_t *tx = (htp_tx_t *)txv;

    if (htp_tx_response_headers(tx) == NULL)
        return false;

    const htp_header_t *h = htp_tx_response_header(tx, "Set-Cookie");
    if (h == NULL || htp_header_value(h) == NULL) {
        SCLogDebug("HTTP cookie header not present in this request");
        return false;
    }

    *data_len = htp_header_value_len(h);
    *data = htp_header_value_ptr(h);
    return true;
}

/******************************** UNITESTS **********************************/

#ifdef UNITTESTS
#include "tests/detect-http-cookie.c"
#endif /* UNITTESTS */

/**
 * @}
 */
