// Local Pure Field Matcher for Veil Agent
// Layered form field matching against Vault keys with high-precision entity recognition.
// Supports Google Forms, HTML5, React/Vue SPAs, and bilingual English/Hindi cues.
// Pure, deterministic, zero network egress.

(() => {
  const AUTOCOMPLETE_MAP = {
    'name': 'FULL_NAME',
    'given-name': 'FIRST_NAME',
    'family-name': 'LAST_NAME',
    'additional-name': 'MIDDLE_NAME',
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
    'country': 'COUNTRY',
    'country-name': 'COUNTRY',
    'organization': 'COMPANY',
    'organization-title': 'JOB_TITLE'
  };

  const SENSITIVE_KEYS = new Set([
    'PASSWORD',
    'AADHAAR',
    'PAN',
    'PASSPORT',
    'VOTER_ID',
    'DRIVING_LICENCE',
    'ACCOUNT_NO',
    'IFSC',
    'CARD_NUMBER',
    'CVV',
    'OTP'
  ]);

  const SYNONYMS = [
    // --- 1. SENSITIVE IDENTIFIERS & CREDENTIALS (ALWAYS SKIPPED) ---
    {
      key: 'PASSWORD',
      isSensitive: true,
      tokens: [
        'password', 'create password', 'enter password', 'new password', 'choose password',
        'confirm password', 'passcode', 'pwd', 'पासवर्ड'
      ],
      negativeTokens: []
    },
    {
      key: 'AADHAAR',
      isSensitive: true,
      tokens: [
        'aadhar card number', 'aadhaar card number', 'aadhaar card', 'aadhar card',
        'aadhaar number', 'aadhar number', 'aadhaar', 'aadhar', 'uid', '12 digit aadhaar',
        '12 digit aadhar', 'आधार', 'आधार संख्या', 'आधार नंबर', 'आधार कार्ड', 'uidai'
      ],
      negativeTokens: []
    },
    {
      key: 'PAN',
      isSensitive: true,
      tokens: [
        'pan card number', 'pan number', 'pan card', 'pan', 'permanent account number',
        'पैन', 'पैन कार्ड', 'पैन नंबर', 'स्थायी खाता संख्या'
      ],
      negativeTokens: ['company pan']
    },
    {
      key: 'PASSPORT',
      isSensitive: true,
      tokens: ['passport number', 'passport no', 'passport', 'पासपोर्ट'],
      negativeTokens: []
    },
    {
      key: 'VOTER_ID',
      isSensitive: true,
      tokens: ['voter id', 'voter card', 'epic number', 'voter id number', 'मतदाता पहचान पत्र'],
      negativeTokens: []
    },
    {
      key: 'DRIVING_LICENCE',
      isSensitive: true,
      tokens: ['driving licence', 'driving license', 'dl number', 'driving license number', 'ड्राइविंग लाइसेंस'],
      negativeTokens: []
    },
    {
      key: 'CARD_NUMBER',
      isSensitive: true,
      tokens: ['card number', 'credit card number', 'debit card number', '16 digit card', 'card no', 'कार्ड नंबर'],
      negativeTokens: []
    },
    {
      key: 'CVV',
      isSensitive: true,
      tokens: ['cvv', 'cvc', 'security code', 'card verification value'],
      negativeTokens: []
    },
    {
      key: 'ACCOUNT_NO',
      isSensitive: true,
      tokens: ['account number', 'bank account number', 'account no', 'bank a c', 'a c no', 'खाता संख्या', 'बैंक खाता'],
      negativeTokens: []
    },
    {
      key: 'IFSC',
      isSensitive: true,
      tokens: ['ifsc code', 'ifsc', 'branch ifsc', 'आईएफएससी कोड'],
      negativeTokens: []
    },
    {
      key: 'OTP',
      isSensitive: true,
      tokens: ['otp', 'one time password', 'verification code', 'security code', 'ओटीपी'],
      negativeTokens: []
    },

    // --- 2. ADDRESS FIELDS ---
    {
      key: 'PERMANENT_ADDRESS',
      tokens: [
        'permanent address', 'permanent residential address', 'home town address',
        'स्थायी पता', 'sthayi pata', 'pakka pata'
      ],
      negativeTokens: ['current', 'present', 'वर्तमान']
    },
    {
      key: 'ADDRESS_LINE2',
      tokens: [
        'address line 2', 'address 2', 'apartment', 'suite', 'landmark', 'area',
        'sector', 'colony', 'पता पंक्ति 2', 'सीमा चिह्न'
      ],
      negativeTokens: ['line 1', 'पंक्ति 1', 'address line 1']
    },
    {
      key: 'ADDRESS_LINE1',
      tokens: [
        'current address', 'present address', 'address', 'residential address',
        'communication address', 'street address', 'flat no', 'house no',
        'house address', 'home address', 'address line 1', 'address 1', 'local address',
        'complete address', 'full address', 'mailing address', 'postal address',
        'पता पंक्ति 1', 'मकान नंबर', 'पता', 'वर्तमान पता', 'आवासीय पता', 'डाक पता',
        'pata line 1', 'makan number', 'pata', 'vartaman pata', 'aawasiya pata'
      ],
      negativeTokens: ['line 2', 'पंक्ति 2', 'permanent address', 'स्थायी पता', 'email', 'ip address', 'mac address', 'ईमेल']
    },
    {
      key: 'CITY',
      tokens: ['city', 'town', 'village', 'city town', 'शहर', 'नगर', 'गाँव', 'shahar', 'nagar'],
      negativeTokens: ['state', 'electricity', 'park', 'favorite']
    },
    {
      key: 'DISTRICT',
      tokens: ['district', 'ज़िला', 'जिला', 'jila', 'zila'],
      negativeTokens: []
    },
    {
      key: 'STATE',
      tokens: ['state', 'province', 'state province', 'राज्य', 'प्रान्त', 'rajya', 'prant'],
      negativeTokens: ['statement']
    },
    {
      key: 'PIN',
      tokens: [
        'pin code', 'pincode', 'pin', 'postal code', 'zip code', 'zip', 'post code',
        'पिन कोड', 'पिनकोड', 'पिन', 'डाक कोड', 'pin code', 'pincode'
      ],
      negativeTokens: ['upi pin', 'atm pin', 'card pin']
    },
    {
      key: 'COUNTRY',
      tokens: ['country', 'nation', 'country of residence', 'देश', 'राष्ट्र', 'desh'],
      negativeTokens: ['country code']
    },

    // --- 3. PERSONAL & DEMOGRAPHIC ---
    {
      key: 'FATHER_NAME',
      tokens: [
        'father name', 'father\'s name', 'fathers name', 'father', 'guardian name', 'parent name',
        'पिता का नाम', 'पिताजी का नाम', 'पिता', 'pita ka naam', 'pitaji ka naam'
      ],
      negativeTokens: []
    },
    {
      key: 'MOTHER_NAME',
      tokens: [
        'mother name', 'mother\'s name', 'mothers name', 'mother',
        'माता का नाम', 'माताजी का नाम', 'माता', 'mata ka naam', 'mataji ka naam'
      ],
      negativeTokens: []
    },
    {
      key: 'SPOUSE_NAME',
      tokens: [
        'spouse name', 'husband name', 'wife name', 'पति का नाम', 'पत्नी का नाम',
        'pati ka naam', 'patni ka naam'
      ],
      negativeTokens: []
    },
    {
      key: 'FIRST_NAME',
      tokens: [
        'first name', 'given name', 'forename', 'fname',
        'पहला नाम', 'प्रथम नाम', 'pehla naam', 'pratham naam'
      ],
      negativeTokens: ['father', 'mother', 'company', 'spouse']
    },
    {
      key: 'LAST_NAME',
      tokens: [
        'last name', 'surname', 'family name', 'lname',
        'अंतिम नाम', 'उपनाम', 'कुलनाम', 'antim naam', 'upnaam'
      ],
      negativeTokens: ['father', 'mother', 'company', 'spouse']
    },
    {
      key: 'MIDDLE_NAME',
      tokens: ['middle name', 'मध्य नाम', 'madhya naam'],
      negativeTokens: []
    },
    {
      key: 'FULL_NAME',
      tokens: [
        'full name', 'applicant name', 'candidate name', 'student name', 'your name',
        'name of applicant', 'name of candidate', 'name', 'person name', 'legal name',
        'पूरा नाम', 'आवेदक का नाम', 'उम्मीदवार का नाम', 'विद्यार्थी का नाम', 'नाम',
        'pura naam', 'aavedak ka naam', 'naam'
      ],
      negativeTokens: [
        'father', 'mother', 'company', 'org', 'organization', 'institution',
        'school', 'college', 'employer', 'bank', 'spouse', 'husband', 'wife',
        'पिता', 'माता', 'कंपनी', 'संस्था'
      ]
    },
    {
      key: 'DOB_DAY',
      tokens: ['dob day', 'birth day', 'day of birth', 'dd', 'जन्म दिन', 'दिन'],
      negativeTokens: ['month', 'year', 'mm', 'yyyy']
    },
    {
      key: 'DOB_MONTH',
      tokens: ['dob month', 'birth month', 'month of birth', 'mm', 'जन्म माह', 'महीना'],
      negativeTokens: ['day', 'year', 'dd', 'yyyy']
    },
    {
      key: 'DOB_YEAR',
      tokens: ['dob year', 'birth year', 'year of birth', 'yyyy', 'जन्म वर्ष', 'साल'],
      negativeTokens: ['day', 'month', 'dd', 'mm']
    },
    {
      key: 'DOB',
      tokens: [
        'date of birth', 'dob', 'birth date', 'birthdate', 'd o b', 'birthday',
        'जन्म तिथि', 'जन्म दिनांक', 'जन्मतिथि', 'जन्म तारीख', 'janm tithi', 'janm dinank'
      ],
      negativeTokens: []
    },
    {
      key: 'GENDER',
      tokens: ['gender', 'sex', 'लिंग', 'ling'],
      negativeTokens: []
    },
    {
      key: 'AGE',
      tokens: ['age', 'उम्र', 'आयु', 'aayu', 'umra'],
      negativeTokens: ['percentage', 'agree']
    },
    {
      key: 'BLOOD_GROUP',
      tokens: ['blood group', 'blood type', 'रक्त समूह'],
      negativeTokens: []
    },
    {
      key: 'MARITAL_STATUS',
      tokens: ['marital status', 'marriage status', 'वैवाहिक स्थिति'],
      negativeTokens: []
    },
    {
      key: 'NATIONALITY',
      tokens: ['nationality', 'citizenship', 'राष्ट्रीयता', 'नागरिकता'],
      negativeTokens: []
    },
    {
      key: 'CATEGORY',
      tokens: [
        'category', 'caste category', 'social category', 'reservation category',
        'श्रेणी', 'वर्ग', 'जाति श्रेणी'
      ],
      negativeTokens: []
    },

    // --- 4. CONTACT DETAILS ---
    {
      key: 'ALT_EMAIL',
      tokens: ['alternate email', 'secondary email', 'alt email', 'backup email'],
      negativeTokens: []
    },
    {
      key: 'WORK_EMAIL',
      tokens: ['work email', 'office email', 'official email', 'business email'],
      negativeTokens: []
    },
    {
      key: 'EMAIL',
      tokens: [
        'email', 'email address', 'e mail', 'e-mail', 'email id', 'e-mail address',
        'ईमेल', 'ई-मेल', 'ईमेल आईडी', 'ईमेल पता', 'email pata'
      ],
      negativeTokens: ['alternate', 'work email', 'office email']
    },
    {
      key: 'ALT_MOBILE',
      tokens: ['alternate mobile', 'alternate phone', 'secondary phone', 'emergency phone', 'alt phone'],
      negativeTokens: []
    },
    {
      key: 'MOBILE_CC',
      tokens: ['country code', 'isd', 'country dial code', 'कंट्री कोड'],
      negativeTokens: []
    },
    {
      key: 'MOBILE',
      tokens: [
        'mobile', 'mobile number', 'phone', 'phone number', 'contact number',
        'cell phone', 'telephone', 'tel no', 'mobile no', 'phone no', 'whatsapp number',
        'whatsapp', 'contact no', 'मोबाइल', 'मोबाइल नंबर', 'फ़ोन', 'फोन', 'संपर्क नंबर'
      ],
      negativeTokens: ['alternate', 'emergency']
    },

    // --- 5. EDUCATION & ACADEMICS ---
    {
      key: 'GRADUATION_YEAR',
      tokens: ['graduation year', 'passing year', 'year of passing', 'passout year', 'batch'],
      negativeTokens: []
    },
    {
      key: 'CGPA',
      tokens: ['cgpa', 'gpa', 'percentage', 'percent', 'marks', 'score', 'grade', 'marks percentage'],
      negativeTokens: []
    },
    {
      key: 'MAJOR',
      tokens: ['major', 'stream', 'branch', 'field of study', 'department', 'specialization', 'discipline'],
      negativeTokens: []
    },
    {
      key: 'DEGREE',
      tokens: [
        'degree', 'qualification', 'highest qualification', 'course', 'program',
        'highest degree', 'educational qualification', 'शिक्षा'
      ],
      negativeTokens: []
    },
    {
      key: 'SCHOOL_12TH',
      tokens: ['12th school', 'class 12', '12th', 'hsc', 'intermediate', 'senior secondary'],
      negativeTokens: ['10th']
    },
    {
      key: 'SCHOOL_10TH',
      tokens: ['10th school', 'class 10', '10th', 'ssc', 'matriculation', 'secondary school'],
      negativeTokens: ['12th']
    },
    {
      key: 'COLLEGE',
      tokens: [
        'college', 'university', 'institute', 'school name', 'institution',
        'college name', 'university name', 'institute name', 'campus', 'alma mater',
        'कॉलेज', 'विश्वविद्यालय', 'संस्थान'
      ],
      negativeTokens: []
    },

    // --- 6. EMPLOYMENT & PROFESSIONAL ---
    {
      key: 'JOB_TITLE',
      tokens: [
        'job title', 'designation', 'role', 'position', 'current role', 'post',
        'designation role', 'job designation', 'व्यवसाय', 'पद'
      ],
      negativeTokens: []
    },
    {
      key: 'EXPERIENCE_YEARS',
      tokens: ['experience', 'years of experience', 'work experience', 'total experience', 'experience in years'],
      negativeTokens: []
    },
    {
      key: 'ANNUAL_SALARY',
      tokens: ['annual salary', 'ctc', 'salary', 'current ctc', 'current salary', 'annual ctc', 'compensation'],
      negativeTokens: []
    },
    {
      key: 'LINKEDIN_URL',
      tokens: ['linkedin', 'linkedin profile', 'linkedin url'],
      negativeTokens: []
    },
    {
      key: 'GITHUB_URL',
      tokens: ['github', 'github profile', 'github url'],
      negativeTokens: []
    },
    {
      key: 'PORTFOLIO_URL',
      tokens: ['portfolio', 'portfolio url', 'website', 'personal website', 'blog url', 'web site'],
      negativeTokens: []
    },
    {
      key: 'COMPANY',
      tokens: [
        'company', 'organization', 'employer', 'firm', 'workplace', 'company name',
        'current company', 'current employer', 'कंपनी'
      ],
      negativeTokens: []
    }
  ];

  const CONSENT_TOKENS = [
    'terms', 'conditions', 'agree', 'declaration', 'consent', 'accept',
    'i agree', 'i accept', 'privacy policy', 'terms of service',
    'सहमति', 'शर्तें', 'घोषणा', 'स्वीकार', 'नियम और शर्तें'
  ];

  function normalizeText(str) {
    if (!str || typeof str !== 'string') return '';
    return str
      .toLowerCase()
      .replace(/\*/g, ' ') // Strip required asterisk
      .replace(/\b(this is a required question|required question|your answer|enter your|please enter|type here|mandatory)\b/gi, ' ')
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
      return { score: 0.99, type: 'exact' };
    }
    if (text.startsWith(token + ' ') || text.endsWith(' ' + token) || text.includes(' ' + token + ' ')) {
      return { score: 0.94, type: 'word_boundary' };
    }
    if (token.length > 3 && text.includes(token)) {
      return { score: 0.88, type: 'substring' };
    }
    if (text.length > 3 && token.includes(text)) {
      return { score: 0.82, type: 'reverse_substring' };
    }
    return null;
  }

  function matchField(node, options = {}) {
    if (!node || typeof node !== 'object') return null;
    const nodeId = node.id || 'unknown';

    // 1. Check if type="password" immediately
    if (node.type === 'password') {
      return {
        nodeId,
        vaultKey: 'PASSWORD',
        isSensitive: true,
        sensitiveType: 'PASSWORD',
        confidence: 1.0,
        reason: 'HTML type="password" (Skipped - Sensitive)'
      };
    }

    // 2. Consent / terms check
    if (isConsentField(node)) {
      return {
        nodeId,
        vaultKey: null,
        isConsent: true,
        confidence: 1.0,
        reason: 'Consent/declaration checkboxes require user approval'
      };
    }

    // 3. HTML Autocomplete hints
    if (node.autocomplete) {
      const acNorm = node.autocomplete.toLowerCase().trim();
      const acKey = AUTOCOMPLETE_MAP[acNorm];
      if (acKey) {
        const isSens = SENSITIVE_KEYS.has(acKey);
        return {
          nodeId,
          vaultKey: acKey,
          isSensitive: isSens,
          sensitiveType: isSens ? acKey : null,
          confidence: 1.0,
          reason: `HTML autocomplete hint: "${node.autocomplete}"`
        };
      }
    }

    // 4. HTML Type hints
    if (node.type === 'email' && !node.label) {
      return {
        nodeId,
        vaultKey: 'EMAIL',
        confidence: 0.92,
        reason: 'HTML type="email"'
      };
    }
    if (node.type === 'date' && !node.label) {
      return {
        nodeId,
        vaultKey: 'DOB',
        confidence: 0.90,
        reason: 'HTML type="date"'
      };
    }

    // 5. Gather candidate texts in order of priority
    const labelText = normalizeText(node.label || node.ariaLabel || '');
    const placeholderText = normalizeText(node.placeholder || '');
    const nearbyText = normalizeText(node.nearbyText || '');
    const nameIdText = normalizeText(`${node.name || ''} ${node.id || ''}`);

    const searchPool = [
      { text: labelText, weight: 1.0, source: 'label' },
      { text: placeholderText, weight: 0.90, source: 'placeholder' },
      { text: nearbyText, weight: 0.85, source: 'nearbyText' },
      { text: nameIdText, weight: 0.75, source: 'name/id' }
    ].filter(item => item.text.length > 0);

    // 6. Match against Synonyms
    let bestMatch = null;
    let highestScore = 0;

    for (const entry of SYNONYMS) {
      for (const poolItem of searchPool) {
        const text = poolItem.text;
        if (hasNegativeToken(text, entry.negativeTokens)) continue;

        for (const token of entry.tokens) {
          const matchResult = matchesToken(text, token);
          if (!matchResult) continue;

          const score = matchResult.score * poolItem.weight;
          if (score > highestScore) {
            highestScore = score;
            const isSens = !!entry.isSensitive || SENSITIVE_KEYS.has(entry.key);
            bestMatch = {
              nodeId,
              vaultKey: entry.key,
              isSensitive: isSens,
              sensitiveType: isSens ? entry.key : null,
              confidence: Math.round(highestScore * 100) / 100,
              reason: `Matched "${token}" (${matchResult.type}) from ${poolItem.source}: "${poolItem.text}"`
            };
          }
        }
      }
    }

    const threshold = options.threshold || 0.60;
    if (bestMatch && bestMatch.confidence >= threshold) {
      return bestMatch;
    }

    return {
      nodeId,
      vaultKey: null,
      confidence: 0,
      reason: 'No confident match found'
    };
  }

  const FieldMatcher = {
    matchField,
    isConsentField,
    normalizeText,
    SYNONYMS,
    AUTOCOMPLETE_MAP,
    SENSITIVE_KEYS
  };

  if (typeof globalThis !== 'undefined') {
    globalThis.FieldMatcher = FieldMatcher;
  }
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = FieldMatcher;
  }
})();
