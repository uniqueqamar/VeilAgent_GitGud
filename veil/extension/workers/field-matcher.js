// Local Pure Field Matcher for Veil Agent (Task 2)
// Matches form fields to vault keys using layered cues:
// Level 1: HTML hints (autocomplete, type, name, id)
// Level 2: Label matching in English and Hindi (Devanagari + transliterated) with synonyms and disambiguation
// Pure, deterministic, zero network calls, unit-tested.

(() => {
  // Autocomplete token to Vault Key mapping
  const AUTOCOMPLETE_MAP = {
    'name': 'FULL_NAME',
    'given-name': 'FIRST_NAME',
    'family-name': 'LAST_NAME',
    'additional-name': 'FIRST_NAME',
    'email': 'EMAIL',
    'tel': 'MOBILE',
    'tel-national': 'MOBILE',
    'tel-country-code': 'MOBILE_CC',
    'bday': 'DOB',
    'bday-day': 'DOB_DAY',
    'bday-month': 'DOB_MONTH',
    'bday-year': 'DOB_YEAR',
    'sex': 'GENDER',
    'street-address': 'ADDRESS_LINE1',
    'address-line1': 'ADDRESS_LINE1',
    'address-line2': 'ADDRESS_LINE2',
    'address-level2': 'CITY',
    'address-level1': 'STATE',
    'postal-code': 'PIN',
    'country': 'STATE'
  };

  // Hindi and English Synonyms dictionary
  const SYNONYMS = [
    {
      key: 'FATHER_NAME',
      tokens: [
        'father name', 'father\'s name', 'fathers name', 'father', 'guardian name', 'parent name',
        'पिता का नाम', 'पिताजी का नाम', 'पिता', 'अभिभावक का नाम', 'अभिभावक',
        'pita ka naam', 'pitaji ka naam', 'pita naam', 'pita', 'guardian'
      ],
      negativeTokens: []
    },
    {
      key: 'MOTHER_NAME',
      tokens: [
        'mother name', 'mother\'s name', 'mothers name', 'mother',
        'माता का नाम', 'माताजी का नाम', 'माता',
        'mata ka naam', 'mataji ka naam', 'mata naam', 'mata'
      ],
      negativeTokens: []
    },
    {
      key: 'FIRST_NAME',
      tokens: [
        'first name', 'given name', 'forename',
        'पहला नाम', 'प्रथम नाम',
        'pehla naam', 'pratham naam'
      ],
      negativeTokens: ['father', 'mother', 'company', 'पिता', 'माता']
    },
    {
      key: 'LAST_NAME',
      tokens: [
        'last name', 'surname', 'family name',
        'अंतिम नाम', 'उपनाम', 'कुलनाम',
        'antim naam', 'upnaam', 'surname'
      ],
      negativeTokens: ['father', 'mother', 'company', 'पिता', 'माता']
    },
    {
      key: 'FULL_NAME',
      tokens: [
        'full name', 'applicant name', 'candidate name', 'student name', 'your name',
        'name of applicant', 'name of candidate', 'name',
        'पूरा नाम', 'आवेदक का नाम', 'उम्मीदवार का नाम', 'विद्यार्थी का नाम', 'नाम',
        'pura naam', 'aavedak ka naam', 'aavedak naam', 'ummidwar ka naam', 'naam'
      ],
      // Exclude near-duplicates that aren't the personal applicant name
      negativeTokens: [
        'father', 'mother', 'company', 'org', 'organization', 'institution',
        'school', 'college', 'employer', 'bank', 'spouse', 'husband', 'wife',
        'पिता', 'माता', 'कंपनी', 'संस्था', 'बैंक', 'पति', 'पत्नी'
      ]
    },
    {
      key: 'EMAIL',
      tokens: [
        'email', 'email address', 'e-mail', 'email id', 'e-mail address',
        'ईमेल', 'ई-मेल', 'ईमेल आईडी', 'ईमेल पता',
        'email id', 'email pata', 'e-mail id'
      ],
      negativeTokens: []
    },
    {
      key: 'DOB_DAY',
      tokens: [
        'dob day', 'birth day', 'day of birth', 'dd',
        'जन्म दिन', 'दिन',
        'janm din', 'din'
      ],
      negativeTokens: ['month', 'year', 'माह', 'वर्ष', 'mm', 'yyyy']
    },
    {
      key: 'DOB_MONTH',
      tokens: [
        'dob month', 'birth month', 'month of birth', 'mm',
        'जन्म माह', 'महीना', 'माह',
        'janm mah', 'mahina', 'mah'
      ],
      negativeTokens: ['day', 'year', 'दिन', 'वर्ष', 'dd', 'yyyy']
    },
    {
      key: 'DOB_YEAR',
      tokens: [
        'dob year', 'birth year', 'year of birth', 'yyyy',
        'जन्म वर्ष', 'साल', 'वर्ष',
        'janm varsh', 'saal', 'varsh'
      ],
      negativeTokens: ['day', 'month', 'दिन', 'माह', 'dd', 'mm']
    },
    {
      key: 'DOB',
      tokens: [
        'date of birth', 'dob', 'birth date', 'birthdate', 'd.o.b',
        'जन्म तिथि', 'जन्म दिनांक', 'जन्मतिथि', 'जन्म तारीख',
        'janm tithi', 'janm dinank', 'janm tarikh', 'janmadin'
      ],
      negativeTokens: []
    },
    {
      key: 'MOBILE_CC',
      tokens: ['country code', 'isd', 'country dial code', 'कंट्री कोड'],
      negativeTokens: []
    },
    {
      key: 'MOBILE_PART1',
      tokens: ['phone part 1', 'mobile 1', 'phone1', 'first 5 digits'],
      negativeTokens: []
    },
    {
      key: 'MOBILE_PART2',
      tokens: ['phone part 2', 'mobile 2', 'phone2', 'last 5 digits'],
      negativeTokens: []
    },
    {
      key: 'MOBILE',
      tokens: [
        'mobile', 'mobile number', 'phone', 'phone number', 'contact number',
        'cell phone', 'telephone', 'tel no', 'mobile no',
        'मोबाइल', 'मोबाइल नंबर', 'फ़ोन', 'फोन', 'संपर्क नंबर', 'दूरभाष',
        'mobile number', 'sampark number', 'phone number', 'chal durhash'
      ],
      negativeTokens: []
    },
    {
      key: 'GENDER',
      tokens: [
        'gender', 'sex',
        'लिंग',
        'ling'
      ],
      negativeTokens: []
    },
    {
      key: 'ADDRESS_LINE1',
      tokens: [
        'address line 1', 'address 1', 'street address', 'house no', 'flat no',
        'address', 'permanent address', 'residential address', 'communication address', 'postal address', 'supply address', 'house address',
        'पता पंक्ति 1', 'मकान नंबर', 'पता', 'स्थायी पता', 'वर्तमान पता', 'आवासीय पता', 'डाक पता',
        'pata line 1', 'makan number', 'pata', 'sthayi pata', 'vartaman pata', 'aawasiya pata'
      ],
      negativeTokens: ['line 2', 'पंक्ति 2', 'email', 'ip address', 'mac address', 'ईमेल']
    },
    {
      key: 'ADDRESS_LINE2',
      tokens: [
        'address line 2', 'address 2', 'apartment', 'suite', 'landmark',
        'पता पंक्ति 2', 'सीमा चिह्न',
        'pata line 2', 'landmark'
      ],
      negativeTokens: ['line 1', 'पंक्ति 1']
    },
    {
      key: 'CITY',
      tokens: [
        'city', 'town', 'village',
        'शहर', 'नगर', 'गाँव',
        'shahar', 'nagar', 'gaon'
      ],
      negativeTokens: ['park', 'favorite', 'feedback', 'survey', 'what', 'which', 'why', 'hotel', 'hall']
    },
    {
      key: 'DISTRICT',
      tokens: [
        'district',
        'ज़िला', 'जिला',
        'jila', 'zila'
      ],
      negativeTokens: []
    },
    {
      key: 'STATE',
      tokens: [
        'state', 'province',
        'राज्य', 'प्रान्त',
        'rajya', 'prant'
      ],
      negativeTokens: []
    },
    {
      key: 'PIN',
      tokens: [
        'pin code', 'pincode', 'pin', 'postal code', 'zip code', 'zip',
        'पिन कोड', 'पिनकोड', 'पिन', 'डाक कोड',
        'pin code', 'pincode', 'daak code', 'post code'
      ],
      negativeTokens: []
    },
    {
      key: 'AADHAAR',
      tokens: [
        'aadhaar', 'aadhar', 'uid', 'aadhaar number', 'aadhar card', '12 digit aadhaar',
        'आधार', 'आधार संख्या', 'आधार नंबर', 'आधार कार्ड',
        'aadhaar number', 'aadhar sankhya', 'aadhar number'
      ],
      negativeTokens: []
    },
    {
      key: 'PAN',
      tokens: [
        'pan number', 'pan card', 'pan', 'permanent account number',
        'पैन', 'पैन कार्ड', 'पैन नंबर', 'स्थायी खाता संख्या',
        'pan number', 'pan card', 'sthayi khata sankhya'
      ],
      negativeTokens: []
    },
    {
      key: 'ACCOUNT_NO',
      tokens: [
        'account number', 'bank account', 'account no', 'bank a/c', 'a/c no', 'savings account',
        'खाता संख्या', 'बैंक खाता', 'खाता नंबर',
        'khata sankhya', 'khata number', 'bank khata'
      ],
      negativeTokens: []
    },
    {
      key: 'IFSC',
      tokens: [
        'ifsc code', 'ifsc', 'branch ifsc',
        'आईएफएससी कोड', 'आईएफएससी',
        'ifsc code', 'ifsc'
      ],
      negativeTokens: []
    },
    {
      key: 'CATEGORY',
      tokens: [
        'category', 'caste category', 'social category', 'reservation category',
        'श्रेणी', 'वर्ग', 'जाति श्रेणी',
        'shreni', 'varg', 'jati shreni'
      ],
      negativeTokens: []
    }
  ];

  // Consent / terms keywords
  const CONSENT_TOKENS = [
    'terms', 'conditions', 'agree', 'declaration', 'consent', 'accept',
    'i agree', 'i accept', 'privacy policy', 'terms of service',
    'सहमति', 'शर्तें', 'घोषणा', 'स्वीकार', 'नियम और शर्तें'
  ];

  function normalizeText(str) {
    if (!str || typeof str !== 'string') return '';
    return str
      .toLowerCase()
      .replace(/[^\w\s\u0900-\u097F-]/g, ' ')
      .replace(/\s+/g, ' ')
      .trim();
  }

  function isConsentField(node) {
    const isCheckOrRadio = (node.type === 'checkbox' || node.tag === 'input' && node.type === 'checkbox');
    if (!isCheckOrRadio) return false;

    const combined = normalizeText([
      node.label,
      node.ariaLabel,
      node.nearbyText,
      node.text,
      node.name,
      node.id
    ].join(' '));

    return CONSENT_TOKENS.some(tok => combined.includes(tok));
  }

  function matchField(node, options = {}) {
    if (!node || typeof node !== 'object') return null;

    const nodeId = node.id || 'unknown';

    // Safety invariant: Check consent / declaration checkboxes
    if (isConsentField(node)) {
      return {
        nodeId,
        vaultKey: null,
        isConsent: true,
        confidence: 1.0,
        reason: 'Consent/declaration checkboxes require user approval'
      };
    }

    // Step 1: HTML Hints (Level 1)
    if (node.autocomplete) {
      const acNorm = node.autocomplete.toLowerCase().trim();
      const acKey = AUTOCOMPLETE_MAP[acNorm];
      if (acKey) {
        return {
          nodeId,
          vaultKey: acKey,
          confidence: 1.0,
          reason: `HTML autocomplete hint: "${node.autocomplete}"`
        };
      }
    }

    // Input type hint (Level 1)
    if (node.type === 'email' && !node.label) {
      return {
        nodeId,
        vaultKey: 'EMAIL',
        confidence: 0.90,
        reason: 'HTML type="email"'
      };
    }

    if (node.type === 'date' && !node.label) {
      return {
        nodeId,
        vaultKey: 'DOB',
        confidence: 0.85,
        reason: 'HTML type="date"'
      };
    }

    // Gather candidate text sources in order of preference
    const labelText = normalizeText(node.label || node.ariaLabel || '');
    const placeholderText = normalizeText(node.placeholder || '');
    const nearbyText = normalizeText(node.nearbyText || '');
    const nameIdText = normalizeText(`${node.name || ''} ${node.id || ''}`);

    const searchPool = [
      { text: labelText, weight: 1.0, source: 'label' },
      { text: placeholderText, weight: 0.88, source: 'placeholder' },
      { text: nearbyText, weight: 0.80, source: 'nearbyText' },
      { text: nameIdText, weight: 0.75, source: 'name/id' }
    ].filter(item => item.text.length > 0);

    // Step 2: Layered matching against Synonyms dictionary
    let bestMatch = null;
    let highestScore = 0;

  function hasNegativeToken(text, negativeTokens) {
    if (!negativeTokens || negativeTokens.length === 0) return false;
    for (const neg of negativeTokens) {
      if (!neg) continue;
      if (text === neg) return true;
      if (neg.length <= 4) {
        if (text.startsWith(neg + ' ') || text.endsWith(' ' + neg) || text.includes(' ' + neg + ' ')) {
          return true;
        }
      } else {
        if (text.includes(neg)) return true;
      }
    }
    return false;
  }

  function matchesToken(text, token) {
    if (!text || !token) return null;
    if (text === token) {
      return { score: 0.98, type: 'exact' };
    }
    if (text.startsWith(token + ' ') || text.endsWith(' ' + token) || text.includes(' ' + token + ' ')) {
      return { score: 0.92, type: 'word_boundary' };
    }
    // Substring match allowed ONLY for tokens longer than 4 characters
    if (token.length > 4 && text.includes(token)) {
      return { score: 0.85, type: 'substring' };
    }
    return null;
  }

    for (const entry of SYNONYMS) {
      for (const poolItem of searchPool) {
        const text = poolItem.text;

        // Check negative tokens first (near-duplicate disambiguation)
        if (hasNegativeToken(text, entry.negativeTokens)) continue;

        for (const token of entry.tokens) {
          const matchResult = matchesToken(text, token);
          if (!matchResult) continue;

          const score = matchResult.score * poolItem.weight;
          const matchType = matchResult.type;

          if (score > highestScore) {
            highestScore = score;
            bestMatch = {
              nodeId,
              vaultKey: entry.key,
              confidence: Math.round(highestScore * 100) / 100,
              reason: `Matched "${token}" (${matchType}) from ${poolItem.source}: "${poolItem.text}"`
            };
          }
        }
      }
    }

    // Reject low confidence matches (Invariant: never guess or fabricate)
    const threshold = options.threshold || 0.60;
    if (bestMatch && bestMatch.confidence >= threshold) {
      return bestMatch;
    }

    return {
      nodeId,
      vaultKey: null,
      confidence: 0,
      reason: 'No confident match found - requires VLM or ask_user'
    };
  }

  const FieldMatcher = {
    matchField,
    isConsentField,
    normalizeText,
    SYNONYMS,
    AUTOCOMPLETE_MAP
  };

  if (typeof globalThis !== 'undefined') {
    globalThis.FieldMatcher = FieldMatcher;
  }
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = FieldMatcher;
  }
})();
