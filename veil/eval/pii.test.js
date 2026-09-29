const { test, describe } = require('node:test');
const assert = require('node:assert');
const path = require('node:path');

const pii = require('../extension/workers/pii.js');

describe('VeilPII Worker Detection Suite', () => {
  test('Email detector handles standard and tagged addresses', () => {
    const text = 'Contact us at support@example.com or user+tag@corp.co.in for help.';
    const findings = pii.detectPII(text);
    const emails = findings.filter((f) => f.type === 'email');
    assert.strictEqual(emails.length, 2);
    assert.strictEqual(emails[0].value, 'support@example.com');
    assert.strictEqual(emails[1].value, 'user+tag@corp.co.in');

    // Invalid email check
    const invalid = pii.detectPII('Not an email: @example.com or user@ or user@domain');
    assert.strictEqual(invalid.filter((f) => f.type === 'email').length, 0);
  });

  test('Indian Mobile detector: +91, 0 prefix, spaces, hyphens, and Devanagari', () => {
    const text = 'Call +91 98765 43210 or 09876543210 or 98765-43210 today.';
    const findings = pii.detectPII(text);
    const mobiles = findings.filter((f) => f.type === 'mobile');
    assert.strictEqual(mobiles.length, 3);

    // Starting with invalid first digit (1-5) must not match
    const nonMobile = pii.detectPII('Order number: 1234567890 or 5876543210');
    assert.strictEqual(nonMobile.filter((f) => f.type === 'mobile').length, 0);

    // Devanagari mobile
    const devText = 'मेरा मोबाइल नंबर +९१ ९८७६५ ४३२१० है';
    const devFindings = pii.detectPII(devText);
    const devMobiles = devFindings.filter((f) => f.type === 'mobile');
    assert.strictEqual(devMobiles.length, 1);
    assert.strictEqual(devMobiles[0].value, '+९१ ९८७६५ ४३२१०');
  });

  test('Aadhaar detector: Verhoeff checksum enforcement, separators, Devanagari', () => {
    // 234567890124 is a mathematically valid Verhoeff Aadhaar number
    const validText = 'My Aadhaar is 2345 6789 0124 and hyphenated 2345-6789-0124';
    const findings = pii.detectPII(validText);
    const aadhaar = findings.filter((f) => f.type === 'aadhaar');
    assert.strictEqual(aadhaar.length, 2);
    assert.strictEqual(aadhaar[0].value, '2345 6789 0124');
    assert.strictEqual(aadhaar[1].value, '2345-6789-0124');

    // Invalid checksum digit 5 (instead of 4) must NEVER be detected as Aadhaar
    const invalidText = 'Aadhaar 2345 6789 0125 and 9999 9999 9999 should not match';
    const invalidFindings = pii.detectPII(invalidText);
    assert.strictEqual(invalidFindings.filter((f) => f.type === 'aadhaar').length, 0);

    // Devanagari Aadhaar digits
    const devAadhaar = 'आधार कार्ड नंबर २३४५ ६७८९ ०१२४ दर्ज करें';
    const devFindings = pii.detectPII(devAadhaar);
    const devAadhaarMatches = devFindings.filter((f) => f.type === 'aadhaar');
    assert.strictEqual(devAadhaarMatches.length, 1);
    assert.strictEqual(devAadhaarMatches[0].value, '२३४५ ६७८९ ०१२४');
  });

  test('Payment Card detector: Luhn checksum enforcement and separators', () => {
    // 4111111111111111 is a valid Luhn test card number
    const validCard = 'Card: 4111 1111 1111 1111 and 4111-1111-1111-1111';
    const findings = pii.detectPII(validCard);
    const cards = findings.filter((f) => f.type === 'card');
    assert.strictEqual(cards.length, 2);

    // Invalid Luhn checksum (last digit 2 instead of 1)
    const invalidCard = 'Card 4111 1111 1111 1112 fails Luhn';
    const invalidFindings = pii.detectPII(invalidCard);
    assert.strictEqual(invalidFindings.filter((f) => f.type === 'card').length, 0);
  });

  test('PAN detector: 5 letters, 4 digits, 1 letter and hard negative checks', () => {
    const text = 'PAN is ABCDE1234F and another BNZPK1234A';
    const findings = pii.detectPII(text);
    const pans = findings.filter((f) => f.type === 'pan');
    assert.strictEqual(pans.length, 2);
    assert.strictEqual(pans[0].value, 'ABCDE1234F');

    // Hex variable should be ignored
    const hex = pii.detectPII('let buffer = 0xABCDE1234F;');
    assert.strictEqual(hex.filter((f) => f.type === 'pan').length, 0);

    // Invalid PAN lengths
    const invalidPan = pii.detectPII('ABCD1234F or 12345ABCDE');
    assert.strictEqual(invalidPan.filter((f) => f.type === 'pan').length, 0);
  });

  test('IFSC detector: 4 letters, 0, 6 alphanumeric', () => {
    const text = 'Bank IFSC: HDFC0001234 or SBIN0000456';
    const findings = pii.detectPII(text);
    const ifscs = findings.filter((f) => f.type === 'ifsc');
    assert.strictEqual(ifscs.length, 2);
    assert.strictEqual(ifscs[0].value, 'HDFC0001234');

    // 5th character not 0
    const invalid = pii.detectPII('IFSC HDFC1001234 is invalid');
    assert.strictEqual(invalid.filter((f) => f.type === 'ifsc').length, 0);
  });

  test('UPI ID detector: handle@provider without email collision', () => {
    const text = 'Pay via user@okhdfcbank or merchant@upi or 9876543210@paytm';
    const findings = pii.detectPII(text);
    const upis = findings.filter((f) => f.type === 'upi');
    assert.strictEqual(upis.length, 3);

    // Standard email must not be tagged as UPI
    const emailOnly = pii.detectPII('Email is contact@google.com');
    assert.strictEqual(emailOnly.filter((f) => f.type === 'upi').length, 0);
    assert.strictEqual(emailOnly.filter((f) => f.type === 'email').length, 1);
  });

  test('Passport and Voter ID detectors', () => {
    const text = 'Passport: A1234567, Voter ID: XYZ1234567';
    const findings = pii.detectPII(text);
    const passport = findings.find((f) => f.type === 'passport');
    const voter = findings.find((f) => f.type === 'voter_id');
    assert.ok(passport);
    assert.strictEqual(passport.value, 'A1234567');
    assert.ok(voter);
    assert.strictEqual(voter.value, 'XYZ1234567');
  });

  test('Driving Licence and Vehicle Plate detectors', () => {
    const text = 'DL: DL0120150001234, Plate: MH 12 AB 1234, BH Series: 22 BH 1234 AB';
    const findings = pii.detectPII(text);
    const dl = findings.find((f) => f.type === 'driving_licence');
    const plate = findings.filter((f) => f.type === 'plate');
    assert.ok(dl);
    assert.strictEqual(dl.value, 'DL0120150001234');
    assert.ok(plate.length >= 1);
  });

  test('classifyField checks passwords, OTPs, and sensitive form controls', () => {
    assert.deepStrictEqual(pii.classifyField({ type: 'password', name: 'pwd' }), {
      sensitive: true,
      pii_type: 'password'
    });
    assert.deepStrictEqual(pii.classifyField({ autocomplete: 'one-time-code', name: 'otp_input' }), {
      sensitive: true,
      pii_type: 'otp'
    });
    assert.deepStrictEqual(pii.classifyField({ label: 'Credit Card Number', name: 'cc_num' }), {
      sensitive: true,
      pii_type: 'card'
    });
    assert.deepStrictEqual(pii.classifyField({ label: 'Aadhaar Card' }), {
      sensitive: true,
      pii_type: 'aadhaar'
    });
    assert.deepStrictEqual(pii.classifyField({ type: 'tel', label: 'Mobile Number' }), {
      sensitive: false,
      pii_type: 'mobile'
    });
  });

  test('ReDoS safety: 100k adversarial input completes within safety budget', () => {
    // 100,000 characters of digits and spaces designed to stress backtracking regexes
    const adversarialText = '9999 '.repeat(20000);
    assert.strictEqual(adversarialText.length, 100000);

    const start = performance.now();
    const findings = pii.detectPII(adversarialText);
    const duration = performance.now() - start;

    console.log(`  Adversarial 100k input scanned in ${duration.toFixed(2)} ms`);
    // Budget is 50 ms + small overhead for text slicing; must easily finish under 100 ms
    assert.ok(duration < 150, `Scan took too long: ${duration} ms`);
    assert.ok(Array.isArray(findings));
  });
});
