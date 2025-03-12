import { NextRequest, NextResponse } from "next/server";
import crypto from "crypto";

const FLW_SECRET_KEY = process.env.FLW_SECRET_KEY || "";

export async function POST(req: NextRequest) {
  try {
    // Read raw request body
    const rawBody = await req.text();
    const headers = req.headers;

    // Get Flutterwave signature
    const receivedSignature = headers.get("verif-hash");
    if (!receivedSignature) {
      console.warn("⚠️ No signature in request");
      return NextResponse.json({ error: "No signature" }, { status: 400 });
    }

    // Generate HMAC hash using Flutterwave secret key
    const expectedSignature = crypto.createHmac("sha256", FLW_SECRET_KEY).update(rawBody).digest("hex");

    // Compare signatures
    if (receivedSignature !== expectedSignature) {
      console.error("❌ Invalid webhook signature");
      return NextResponse.json({ error: "Invalid signature" }, { status: 400 });
    }

    // Parse and log the verified webhook payload
    const event = JSON.parse(rawBody);
    console.log("📩 Verified Webhook Data:", JSON.stringify(event, null, 2));

    // Handle only successful transactions
    if (event.event === "transfer.completed" && event.data.status === "SUCCESSFUL") {
      console.log("✅ Transfer Successful:", event.data);
    }

    return NextResponse.json({ status: "success" }, { status: 200 });
  } catch (error: any) {
    console.error("❌ Webhook Handling Error:", error);
    return NextResponse.json({ status: "error", error: error.message }, { status: 500 });
  }
}
