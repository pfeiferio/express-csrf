import crypto from "crypto";

export const compareSignatures = (signatureA: Buffer<ArrayBuffer>, signatureB: Buffer<ArrayBuffer>) => {
  if (signatureA.length !== signatureB.length) return false
  return crypto.timingSafeEqual(signatureA, signatureB)
}
