package com.techStack.authSys.payment.dto.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

/**
 * Deserialized M-Pesa STK Push callback from Safaricom.
 * POST /api/payments/mpesa/callback
 *
 * Safaricom sends this payload asynchronously after the customer
 * confirms or cancels the STK push on their phone.
 *
 * Full payload shape (SUCCESS example):
 * {
 *   "Body": {
 *     "stkCallback": {
 *       "MerchantRequestID": "29115-34620561-1",
 *       "CheckoutRequestID": "ws_CO_191220191020363925",
 *       "ResultCode": 0,
 *       "ResultDesc": "The service request is processed successfully.",
 *       "CallbackMetadata": {
 *         "Item": [
 *           { "Name": "Amount",              "Value": 1000 },
 *           { "Name": "MpesaReceiptNumber",  "Value": "QHT7AN6BA2" },
 *           { "Name": "TransactionDate",     "Value": 20191219102115 },
 *           { "Name": "PhoneNumber",         "Value": 254712345678 }
 *         ]
 *       }
 *     }
 *   }
 * }
 *
 * On failure (e.g. cancelled): CallbackMetadata is absent, ResultCode != 0.
 */
@Data
public class MpesaCallbackRequest {

    @JsonProperty("Body")
    private Body body;

    @Data
    public static class Body {
        @JsonProperty("stkCallback")
        private StkCallback stkCallback;
    }

    @Data
    public static class StkCallback {
        @JsonProperty("MerchantRequestID")
        private String merchantRequestId;

        @JsonProperty("CheckoutRequestID")
        private String checkoutRequestId;

        @JsonProperty("ResultCode")
        private int resultCode;

        @JsonProperty("ResultDesc")
        private String resultDesc;

        @JsonProperty("CallbackMetadata")
        private CallbackMetadata callbackMetadata;
    }

    @Data
    public static class CallbackMetadata {
        @JsonProperty("Item")
        private java.util.List<MetadataItem> item;
    }

    @Data
    public static class MetadataItem {
        @JsonProperty("Name")
        private String name;

        @JsonProperty("Value")
        private Object value; // Safaricom sends mixed types (String/Number)

        public String getValueAsString() {
            return value != null ? value.toString() : null;
        }
    }

    // ── Convenience accessors ────────────────────────────────────────────────

    public StkCallback getStkCallback() {
        return body != null ? body.getStkCallback() : null;
    }

    public boolean isSuccess() {
        StkCallback cb = getStkCallback();
        return cb != null && cb.getResultCode() == 0;
    }

    public boolean isCancelledByUser() {
        StkCallback cb = getStkCallback();
        return cb != null && cb.getResultCode() == 1032;
    }

    /**
     * Extract a named item value from CallbackMetadata.
     * e.g. getMetadataValue("MpesaReceiptNumber") → "QHT7AN6BA2"
     */
    public String getMetadataValue(String name) {
        StkCallback cb = getStkCallback();
        if (cb == null || cb.getCallbackMetadata() == null
                || cb.getCallbackMetadata().getItem() == null) return null;
        return cb.getCallbackMetadata().getItem().stream()
            .filter(i -> name.equals(i.getName()))
            .map(MetadataItem::getValueAsString)
            .findFirst()
            .orElse(null);
    }
}
