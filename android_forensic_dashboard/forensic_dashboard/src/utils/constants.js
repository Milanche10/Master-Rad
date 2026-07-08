// Dizajn tokeni — sve boje i tipografija na jednom mestu
export const C = {
  // Pozadine — duboke navy/slate nijanse, ne čisto crna
  bg:         '#080c14',
  bgPanel:    '#0d1117',
  bgCard:     '#111927',
  bgCardHover:'#141e2e',
  bgInput:    '#0a1020',

  // Borders
  border:     '#1a2640',
  borderFocus:'#2d4a7a',

  // Akcent — hladna cijan/azure nijansa
  accent:     '#4d9fff',
  accentDim:  '#0d2040',
  accentGlow: '#4d9fff33',

  // Statusi
  green:      '#3fb950',
  greenDim:   '#0d2618',
  yellow:     '#d29922',
  yellowDim:  '#2a1f06',
  red:        '#f85149',
  redDim:     '#2d0e0e',
  orange:     '#e3893d',
  orangeDim:  '#2d1a06',
  purple:     '#a371f7',
  purpleDim:  '#1a0d33',

  // Tekst
  textPrimary:   '#e6edf3',
  textSecondary: '#7d8fa6',
  textMuted:     '#3d4f6a',
  textCode:      '#79c0ff',

  // Tipografija
  fontSans: "'IBM Plex Sans', sans-serif",
  fontMono: "'IBM Plex Mono', monospace",
};

// Definicija svih modula
export const MODULES = [
  {
    id: 'device_info',
    icon: '⬡',        // hexagon — jedinstveni identifikator
    label: 'Identifikacija uređaja',
    desc: 'build.prop · JWT · Google nalog',
    artifactTypes: ['account'],
  },
  {
    id: 'sms',
    icon: '◈',        // poruka
    label: 'SMS / MMS',
    desc: 'mmssms.db · AES detekcija · OmniNotes',
    artifactTypes: ['comm'],
  },
  {
    id: 'calllog',
    icon: '◎',        // poziv / krug
    label: 'Istorija poziva',
    desc: 'calllog.db · 0-sec pozivi',
    artifactTypes: ['call'],
  },
  {
    id: 'contacts',
    icon: '◉',
    label: 'Kontakti',
    desc: 'contacts2.db · sumnjivi nazivi',
    artifactTypes: ['contact'],
  },
  {
    id: 'browser',
    icon: '◫',
    label: 'Browser',
    desc: 'Chrome History · Login Data · Cookies',
    artifactTypes: ['web', 'account'],
  },
  {
    id: 'wifi',
    icon: '◬',
    label: 'WiFi konfiguracije',
    desc: 'WifiConfigStore.xml · geolokacija',
    artifactTypes: ['location'],
  },
  {
    id: 'apk',
    icon: '◧',
    label: 'APK / DEX analiza',
    desc: 'Side-loaded · statička analiza',
    artifactTypes: ['app'],
  },
  {
    id: 'exif',
    icon: '◰',
    label: 'EXIF / GPS',
    desc: 'DCIM · koordinate · timestamp',
    artifactTypes: ['location', 'media'],
  },
  {
    id: 'crypto',
    icon: '◈',
    label: 'Kriptovalute',
    desc: 'QR kodovi · BRD Wallet · P2P',
    artifactTypes: ['crypto'],
  },
  {
    id: 'mp3_signal',
    icon: '◒',
    label: 'MP3 / Audio',
    desc: 'Steganografija · signal pattern',
    artifactTypes: ['media'],
  },
  {
    id: 'blockchain',
    icon: '◆',
    label: 'Blockchain',
    desc: 'ETH · BCH · verifikacija (external)',
    artifactTypes: ['crypto'],
  },
  {
    id: 'signal_brd',
    icon: '◑',
    label: 'Signal + BRD',
    desc: 'SQLCipher metapodaci · wallet DB',
    artifactTypes: ['comm', 'crypto'],
  },
  {
    id: 'app_messaging',
    icon: '◈',
    label: 'App poruke',
    desc: 'WhatsApp · Viber · Telegram · Instagram...',
    artifactTypes: ['message', 'app'],
  },
  {
    id: 'notes',
    icon: '▢',
    label: 'Beleške',
    desc: 'Samsung Notes · Keep · ColorNote',
    artifactTypes: ['note'],
  },
  {
    id: 'reminders',
    icon: '◔',
    label: 'Podsetnici',
    desc: 'Reminder · Tasks · alarmi · kalendar',
    artifactTypes: ['reminder'],
  },
  {
    id: 'deleted_recovery',
    icon: '♻',
    label: 'Obrisani podaci',
    desc: 'SQLite freelist · WAL · trash · thumbs',
    artifactTypes: ['file', 'media'],
  },
  {
    id: 'anti_forensics',
    icon: '⚠',
    label: 'Anti-forenzika',
    desc: 'Obrisano · vreme · root · lažni GPS',
    artifactTypes: ['anti_forensic'],
  },
];

// Boje po tipu artefakta
export const ARTIFACT_COLORS = {
  comm:          C.accent,
  message:       C.accent,
  call:          C.green,
  location:      C.yellow,
  web:           C.purple,
  crypto:        C.orange,
  app:           C.red,
  media:         C.textSecondary,
  account:       C.accent,
  contact:       C.green,
  note:          C.yellow,
  reminder:      C.orange,
  file:          C.textSecondary,
  anti_forensic: C.red,
};

export const ARTIFACT_ICONS = {
  comm:          '◈',
  message:       '◈',
  call:          '◎',
  location:      '◬',
  web:           '◫',
  crypto:        '◆',
  app:           '◧',
  media:         '◒',
  account:       '⬡',
  contact:       '◉',
  note:          '▢',
  reminder:      '◔',
  file:          '▤',
  anti_forensic: '⚠',
};

export const CONFIDENCE_COLORS = {
  VISOKA:  '#f85149',
  SREDNJA: '#e3893d',
  NISKA:   '#d29922',
};
