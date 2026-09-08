package com.techStack.authSys.tour.services;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.openhtmltopdf.pdfboxout.PdfRendererBuilder;
import com.techStack.authSys.tour.dto.pdf.QuotePdfData;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;
import org.springframework.util.StreamUtils;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import java.io.ByteArrayOutputStream;
import java.util.Base64;

@Slf4j
@Service
public class QuotePdfService {

    private final TemplateEngine templateEngine;

    @Value("classpath:static/images/logo.png")
    private ClassPathResource logoResource;

    // Damuchi Tours payment details — update if these ever change
    private static final String MPESA_PAYBILL = "522522";
    private static final String MPESA_ACCOUNT = "2037863";
    private static final String BANK_NAME = "KCB Bank Kenya";
    private static final String BANK_ACCOUNT_NUMBER = "1091234323";
    private static final String BANK_ACCOUNT_NAME = "Damuchi Tours";
    private static final String BANK_BRANCH = "Mtwapa";
    private static final String BANK_SWIFT = "KCBLKENX"; // ⚠️ placeholder — confirm real SWIFT/BIC with KCB

    public QuotePdfService(TemplateEngine templateEngine) {
        this.templateEngine = templateEngine;
    }

    /**
     * Renders a branded, production-ready quote document as PDF bytes.
     * Pure function: takes only primitives, touches no lazy entities,
     * safe to call outside any transaction.
     */
    public byte[] generate(QuotePdfData data) {
        try {
            String logoBase64 = loadLogoAsBase64();
            String qrCodeBase64 = generateQrCode(data.verificationUrl());

            Context ctx = new Context();
            ctx.setVariable("q", data);
            ctx.setVariable("logoBase64", logoBase64);
            ctx.setVariable("qrCodeBase64", qrCodeBase64);
            ctx.setVariable("mpesaPaybill", MPESA_PAYBILL);
            ctx.setVariable("mpesaAccount", MPESA_ACCOUNT);
            ctx.setVariable("bankName", BANK_NAME);
            ctx.setVariable("bankAccountNumber", BANK_ACCOUNT_NUMBER);
            ctx.setVariable("bankAccountName", BANK_ACCOUNT_NAME);
            ctx.setVariable("bankBranch", BANK_BRANCH);
            ctx.setVariable("bankSwift", BANK_SWIFT);

            String html = templateEngine.process("pdf/quote-document", ctx);

            ByteArrayOutputStream os = new ByteArrayOutputStream();
            PdfRendererBuilder builder = new PdfRendererBuilder();
            builder.useFastMode();
            builder.withHtmlContent(html, null);
            builder.toStream(os);
            builder.run();

            return os.toByteArray();
        } catch (Exception e) {
            log.error("Failed to generate quote PDF for quote {}: {}", data.quoteId(), e.getMessage(), e);
            throw new RuntimeException("Quote PDF generation failed", e);
        }
    }

    private String loadLogoAsBase64() throws Exception {
        byte[] bytes = StreamUtils.copyToByteArray(logoResource.getInputStream());
        return Base64.getEncoder().encodeToString(bytes);
    }

    private String generateQrCode(String content) throws WriterException, java.io.IOException {
        QRCodeWriter writer = new QRCodeWriter();
        BitMatrix matrix = writer.encode(content, BarcodeFormat.QR_CODE, 200, 200);
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        MatrixToImageWriter.writeToStream(matrix, "PNG", os);
        return Base64.getEncoder().encodeToString(os.toByteArray());
    }
}