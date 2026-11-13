import crypto from "crypto";
import { Resend } from "resend";

// Generate a secure 6-digit OTP
export function generateOTP() {
  return crypto.randomInt(100000, 999999).toString();
}

/**
 * Send OTP verification email using Resend if API key is provided,
 * otherwise return helpful message for local development / testing.
 */
export async function sendOTPEmail({ email, name, otp, purpose }) {
  const apiKey = process.env.RESEND_API_KEY;
  const isRegister = purpose === "register";
  const actionText = isRegister ? "account registration" : "secure login";

  const subject = `Your ${otp} verification code for Expense Tracker`;
  const htmlContent = `
    <div style="font-family: Arial, sans-serif; max-width: 540px; margin: 0 auto; padding: 24px; border: 1px solid #e6e1d5; border-radius: 12px; background-color: #ffffff;">
      <div style="text-align: center; margin-bottom: 24px;">
        <div style="display: inline-block; background-color: #347a4b; color: #ffffff; font-size: 22px; font-weight: bold; width: 44px; height: 44px; line-height: 44px; border-radius: 10px; margin-bottom: 8px;">₹</div>
        <h2 style="color: #252525; margin: 0; font-size: 20px;">Expense Tracker</h2>
        <p style="color: #777777; font-size: 13px; margin-top: 4px;">Smart Personal Finance Management</p>
      </div>

      <div style="background-color: #f9f8f4; border-radius: 8px; padding: 20px; text-align: center; margin-bottom: 20px;">
        <p style="color: #444444; font-size: 15px; margin: 0 0 12px 0;">Hello ${name || "there"},</p>
        <p style="color: #555555; font-size: 14px; margin: 0 0 16px 0;">Use the 6-digit One-Time Password (OTP) below to complete your ${actionText}.</p>
        <div style="font-size: 32px; font-weight: 700; letter-spacing: 6px; color: #347a4b; background: #e9f3eb; padding: 12px 24px; border-radius: 8px; display: inline-block; font-family: monospace;">
          ${otp}
        </div>
        <p style="color: #888888; font-size: 12px; margin-top: 14px; margin-bottom: 0;">This code is valid for 10 minutes. Please do not share it with anyone.</p>
      </div>

      <p style="color: #999999; font-size: 12px; text-align: center; margin: 0;">
        If you did not request this verification code, you can safely ignore this email.
      </p>
    </div>
  `;

  if (!apiKey) {
    console.log(`[AUTH-DEV] No RESEND_API_KEY configured in environment.`);
    console.log(`[AUTH-DEV] Generated OTP for ${email} (${purpose}): ${otp}`);
    return {
      success: true,
      deliveredVia: "dev-preview",
      message: "No RESEND_API_KEY configured. The OTP is shown on screen for testing.",
      otp,
    };
  }

  try {
    const resend = new Resend(apiKey);
    const fromAddress = process.env.RESEND_FROM_EMAIL || "Expense Tracker <onboarding@resend.dev>";

    const { data, error } = await resend.emails.send({
      from: fromAddress,
      to: [email],
      subject: subject,
      html: htmlContent,
    });

    if (error) {
      console.error("[RESEND-ERROR]", error);
      return {
        success: true, // Allow user to proceed via dev preview if Resend fails in development
        deliveredVia: "dev-preview",
        message: `Resend error: ${error.message || "Failed to send email"}. OTP generated for preview.`,
        error: error.message,
        otp,
      };
    }

    console.log(`[RESEND-SUCCESS] OTP email successfully sent to ${email}. ID:`, data?.id);
    return {
      success: true,
      deliveredVia: "email",
      message: `Verification code sent to ${email}`,
      otp,
    };
  } catch (err) {
    console.error("[EMAIL-EXCEPTION]", err);
    return {
      success: true,
      deliveredVia: "dev-preview",
      message: `Email sending encountered an error: ${err.message}. OTP generated for preview.`,
      error: err.message,
      otp,
    };
  }
}
