import { useState } from '@wordpress/element';
import { 
  ShieldAlert, 
  ShieldCheck, 
  Server, 
  Zap, 
  ExternalLink, 
  CheckCircle2, 
  Wrench, 
  HardDrive, 
  Activity, 
  Network, 
  ArrowRightLeft, 
  Building2, 
  Sparkles, 
  Award, 
  Mail, 
  Phone, 
  Star, 
  Clock, 
  Lock, 
  ArrowRight, 
  Globe, 
  MessageSquare,
  Users
} from 'lucide-react';
import WebCareBrandLogo from './components/WebCareBrandLogo';

interface ServiceItem {
  id: string;
  category: 'security' | 'server' | 'speed' | 'care';
  title: string;
  badge: string;
  description: string;
  features: string[];
  icon: any;
  href: string;
  badgeColor?: string;
  badgeBg?: string;
}

const UPWORK_PROFILE_URL = 'https://www.upwork.com/freelancers/~0162afa9a578170c67';
const TEAMS_INVITE_URL = 'https://teams.live.com/l/invite/FEAI60zv48mwbIKhA?v=g1';

const SERVICES: ServiceItem[] = [
  {
    id: 'hack-recovery',
    category: 'security',
    title: 'Website Hack Recovery & Security',
    badge: 'Emergency SLA',
    description: 'Rapid malware & backdoor cleanup, malicious redirect removal, Google blacklist appeals, and comprehensive server hardening.',
    features: [
      'Immediate malware, webshell & backdoor eradication',
      'Google Search Console & security blacklist delisting',
      'Web Application Firewall (WAF) & zero-day rule setup',
      'Root credentials overhaul & database credential security',
    ],
    icon: ShieldAlert,
    href: 'https://webcarepro.dev/services/website-hack-recovery-security',
    badgeColor: '#e11d48',
    badgeBg: '#ffe4e6'
  },
  {
    id: 'speed-optimization',
    category: 'speed',
    title: 'Website Speed Optimization',
    badge: '100/100 Core Web Vitals',
    description: 'Sub-100ms TTFB server response tuning, Redis object caching, asset deferral, and green Core Web Vitals across mobile & desktop.',
    features: [
      'Sub-100ms TTFB & FastCGI page caching configuration',
      'Redis object caching & MySQL buffer pool optimization',
      'Critical path CSS extraction & non-blocking JS deferral',
      'WooCommerce cart & checkout speed tuning',
    ],
    icon: Zap,
    href: 'https://webcarepro.dev/services/website-speed-optimization',
    badgeColor: '#059669',
    badgeBg: '#d1fae5'
  },
  {
    id: 'managed-server',
    category: 'server',
    title: 'Managed Server Administration',
    badge: 'Linux Root SysAdmin',
    description: 'Full root Linux VPS & dedicated server management, high-concurrency Nginx tuning, CSF/UFW firewalls, and 24/7 origin health monitoring.',
    features: [
      'Full SSH root access & Linux OS security hardening',
      'Nginx, Apache & LiteSpeed high-concurrency architecture',
      'UFW/CSF firewall & Fail2ban automated intrusion defense',
      'Linux kernel patches, swap allocation & load monitoring',
    ],
    icon: Server,
    href: 'https://webcarepro.dev/services/managed-server-administration',
    badgeColor: '#4f46e5',
    badgeBg: '#e0e7ff'
  },
  {
    id: 'web-maintenance',
    category: 'care',
    title: 'Expert Web Maintenance',
    badge: '24/7 Care Plans',
    description: 'Proactive round-the-clock uptime monitoring, safe staging updates, automated offsite cloud backups, and regular database audits.',
    features: [
      'WordPress core, theme & plugin updates tested on staging',
      '24/7 continuous origin uptime & latency monitoring',
      'Automated daily/weekly offsite encrypted cloud backups',
      'Regular database defragmentation & transient cleanup',
    ],
    icon: Wrench,
    href: 'https://webcarepro.dev/services/expert-web-maintenance',
    badgeColor: '#2563eb',
    badgeBg: '#dbeafe'
  },
  {
    id: 'website-transfers',
    category: 'care',
    title: 'Zero-Downtime Website Transfers',
    badge: 'Zero Downtime',
    description: 'Flawless server migrations with live WooCommerce order delta synchronization, database integrity checks, and DNS TTL staging.',
    features: [
      'Guaranteed zero service disruption during cutover',
      'Live WooCommerce order delta syncing (no lost sales)',
      'Database schema, collation & prefix reconciliation',
      'Business email, mailboxes & SSL certificate preservation',
    ],
    icon: ArrowRightLeft,
    href: 'https://webcarepro.dev/services/website-transfer',
    badgeColor: '#0891b2',
    badgeBg: '#cffafe'
  },
  {
    id: 'server-troubleshooting',
    category: 'server',
    title: 'Server & Web Troubleshooting',
    badge: 'No Fix, No Fee',
    description: 'Emergency diagnosis and repair for HTTP 500, 502, 503 errors, PHP fatal memory crashes, database deadlocks, and White Screen of Death.',
    features: [
      'Emergency response triage within 15 minutes',
      'Resolution of HTTP 500, 502 Bad Gateway & 504 Timeouts',
      'Deep server error log analysis & PHP backtrace debugging',
      'Backed by our transparent "No Fix, No Fee" guarantee',
    ],
    icon: Activity,
    href: 'https://webcarepro.dev/services/website-server-troubleshooting',
    badgeColor: '#d97706',
    badgeBg: '#fef3c7'
  },
  {
    id: 'domain-dns',
    category: 'speed',
    title: 'Domain & DNS Setup',
    badge: 'Cloudflare & Email Auth',
    description: 'Enterprise Cloudflare Edge Caching, bot defense, safe DNS cutovers, and SPF/DKIM/DMARC records for 100% email deliverability.',
    features: [
      'Cloudflare Edge caching rules, WAF & Bot Fight Mode',
      'SPF, DKIM & DMARC records for in-box email delivery',
      'Google Workspace, Microsoft 365 & Zoho MX configuration',
      'SEO-preserving 301 redirection & safe DNS propagation',
    ],
    icon: Network,
    href: 'https://webcarepro.dev/services/domain-dns-setup',
    badgeColor: '#7c3aed',
    badgeBg: '#ede9fe'
  },
  {
    id: 'hosting-management',
    category: 'care',
    title: 'Web Hosting Management',
    badge: 'cPanel & Plesk Care',
    description: 'End-to-end management for cPanel, Plesk, and shared hosting control panels without requiring root server access.',
    features: [
      'cPanel, Plesk & hosting control panel management',
      'SSL certificate installations & auto-renewal enforcement',
      'PHP version upgrades, memory limit & php.ini tuning',
      'Business email mailboxes, disk quotas & spam filters',
    ],
    icon: HardDrive,
    href: 'https://webcarepro.dev/services/website-hosting-maintenance',
    badgeColor: '#0d9488',
    badgeBg: '#ccfbf1'
  },
  {
    id: 'white-label',
    category: 'care',
    title: 'White-Label Agency Support',
    badge: 'Agency Partner',
    description: 'Behind-the-scenes senior Linux sysadmin & technical partner for digital agencies, with a 15-minute SLA and NDA protection.',
    features: [
      '100% invisible behind-the-scenes technical execution',
      'Guaranteed 15-minute emergency SLA for client downtime',
      'Mutual Non-Disclosure Agreement (NDA) protected',
      'Direct Slack/Teams integration or branded agency email',
    ],
    icon: Building2,
    href: 'https://webcarepro.dev/services/white-label-agency-support',
    badgeColor: '#059669',
    badgeBg: '#d1fae5'
  },
  {
    id: 'ai-development',
    category: 'speed',
    title: 'AI-Ready Web Development',
    badge: 'WebMCP & Next.js',
    description: 'Modern Next.js web applications engineered for 100/100 Core Web Vitals, rich schema structured data, and WebMCP AI agent discovery.',
    features: [
      'High-performance Next.js & React modern web architectures',
      'WebMCP protocol & semantic llms.txt discovery readiness',
      'Embedded JSON-LD Schema.org for Google AI Overviews',
      'Mobile-first, accessible (a11y) & conversion-focused UX',
    ],
    icon: Sparkles,
    href: 'https://webcarepro.dev/services/seo-website-development',
    badgeColor: '#4f46e5',
    badgeBg: '#e0e7ff'
  }
];

export const AboutServicesPage = () => {
  const [selectedCategory, setSelectedCategory] = useState<string>('all');

  // Dynamically resolve website title and domain name
  const rawSiteUrl = (window as any).webcareScannerSettings?.siteUrl || window.location.origin || '';
  const siteName = (window as any).webcareScannerSettings?.siteName || (document.title ? document.title.split('‹')[0].replace('Dashboard', '').trim() : 'My WordPress Site') || 'My WordPress Site';
  
  let domain = '';
  try {
    domain = new URL(rawSiteUrl || window.location.href).hostname;
  } catch (e) {
    domain = window.location.hostname || '';
  }

  // Prebuilt WhatsApp message containing site title and domain name
  const prebuiltWhatsappUrl = `https://wa.me/8801322691090?text=${encodeURIComponent(
    `Hello WebCare Pro, I need technical assistance with my website "${siteName}" (${domain || rawSiteUrl}).`
  )}`;

  // Prebuilt Email message containing site title and domain name
  const prebuiltEmailUrl = `mailto:hello@webcarepro.dev?subject=${encodeURIComponent(
    `Inquiry regarding ${siteName} (${domain || rawSiteUrl}) - WebCare Pro Services`
  )}&body=${encodeURIComponent(
    `Hello Mir Alamin (WebCare Pro),\n\nI need technical assistance and would like to inquire about your services for my website.\n\nWebsite Title: ${siteName}\nDomain / URL: ${domain || rawSiteUrl}\nServices / Issues: \nPreferred Contact Method: \n\nThank you!`
  )}`;

  const categories = [
    { id: 'all', label: 'All Services (10)' },
    { id: 'security', label: 'Security & Malware' },
    { id: 'server', label: 'Server & SysAdmin' },
    { id: 'speed', label: 'Speed & Performance' },
    { id: 'care', label: 'Care, Migration & Agency' },
  ];

  const filteredServices = selectedCategory === 'all'
    ? SERVICES
    : SERVICES.filter(s => s.category === selectedCategory);

  return (
    <div className="webcare-about-page">
      {/* Hero Banner */}
      <div className="webcare-about-hero">
        <div className="webcare-about-hero-content">
          <div className="webcare-about-pill">
            <WebCareBrandLogo size={18} style={{ marginRight: 6 }} />
            ENGINEERED BY WEBCARE PRO • 12+ YEARS ENTERPRISE LINUX & WEB ARCHITECTURE
          </div>
          <h1 className="webcare-about-title">
            Enterprise Linux Systems & WordPress Engineering
          </h1>
          <p className="webcare-about-desc">
            WebCare Pro helps businesses build, secure, optimize, and manage high-performance websites and servers. From Linux & cloud infrastructure to blazing-fast performance, website security, migrations, Cloudflare, DNS, managed hosting, and modern web development—keeping your online presence fast, secure, and always available.
          </p>

          <div className="webcare-about-hero-actions">
            <a 
              href="https://webcarepro.dev/" 
              target="_blank" 
              rel="noopener noreferrer" 
              className="webcare-btn webcare-btn-primary"
            >
              <Globe size={18} />
              Visit Official Website
              <ExternalLink size={15} />
            </a>
            <a 
              href="https://webcarepro.dev/contact" 
              target="_blank" 
              rel="noopener noreferrer" 
              className="webcare-btn webcare-btn-emergency"
            >
              <ShieldAlert size={18} />
              Emergency Support
            </a>
            <a 
              href={prebuiltWhatsappUrl} 
              target="_blank" 
              rel="noopener noreferrer" 
              className="webcare-btn webcare-btn-whatsapp"
            >
              <MessageSquare size={18} />
              WhatsApp Direct
            </a>
            <a 
              href={TEAMS_INVITE_URL} 
              target="_blank" 
              rel="noopener noreferrer" 
              className="webcare-btn webcare-btn-teams"
            >
              <Users size={18} />
              MS Teams Meeting
            </a>
            <a 
              href={prebuiltEmailUrl} 
              className="webcare-btn webcare-btn-outline"
            >
              <Mail size={18} />
              Email Direct
            </a>
          </div>
        </div>

        {/* Quick Credibility Ticker */}
        <div className="webcare-about-stats-strip">
          <div className="webcare-stat-box">
            <div className="webcare-stat-num">680+</div>
            <div className="webcare-stat-label">Client Projects Delivered</div>
          </div>
          <div className="webcare-stat-box">
            <div className="webcare-stat-num">100%</div>
            <div className="webcare-stat-label">Job Success Score</div>
          </div>
          <div className="webcare-stat-box">
            <div className="webcare-stat-num">12+ Years</div>
            <div className="webcare-stat-label">Enterprise Experience</div>
          </div>
          <div className="webcare-stat-box">
            <div className="webcare-stat-num">&lt; 15 min</div>
            <div className="webcare-stat-label">Emergency Triage Response</div>
          </div>
        </div>
      </div>

      {/* About Us Card */}
      <div className="webcare-founder-card">
        <div className="webcare-founder-badge-row">
          <span className="webcare-founder-label">
            <Award size={16} /> About WebCare Pro
          </span>
          <span className="webcare-founder-tag">Direct Senior Engineering • No Junior Outsourcing</span>
        </div>
        <div className="webcare-founder-body">
          <div className="webcare-founder-text">
            <h3>WebCare Pro — Dedicated Web & Linux Server Engineering</h3>
            <p style={{ fontSize: '15px', lineHeight: '1.7', fontWeight: 500, opacity: 0.9 }}>
              WebCare Pro helps businesses build, secure, optimize, and manage high-performance websites and servers. From Linux & cloud infrastructure to blazing-fast performance, website security, migrations, Cloudflare, DNS, managed hosting, and modern web development—keeping your online presence fast, secure, and always available.
            </p>
            <p style={{ fontSize: '14px', lineHeight: '1.6', opacity: 0.8 }}>
              Led by <strong>Mir Alamin</strong> (Senior Linux SysAdmin & Web Server Architect with over 12 years of hands-on experience since 2013), every technical architecture, complex malware cleanup, and speed optimization is personally executed with direct senior oversight and zero junior contractor outsourcing.
            </p>
          </div>
          <div className="webcare-founder-sidebar">
            <div className="webcare-founder-meta-item">
              <Clock size={16} color="#3b82f6" />
              <div>
                <strong>Founded:</strong> 2013 (12+ Years)
              </div>
            </div>
            <div className="webcare-founder-meta-item">
              <Globe size={16} color="#10b981" />
              <div>
                <strong>Global Reach:</strong> Worldwide Clients
              </div>
            </div>
            <a 
              href={UPWORK_PROFILE_URL} 
              target="_blank" 
              rel="noopener noreferrer" 
              className="webcare-founder-link-item"
              title="View verified Upwork Freelancer profile"
            >
              <Star size={16} color="#f59e0b" />
              <div>
                <strong>Upwork Profile:</strong> 100% Job Success
                <span className="webcare-chat-tag webcare-chat-tag-verified">Verified</span>
              </div>
            </a>
            <a 
              href={TEAMS_INVITE_URL} 
              target="_blank" 
              rel="noopener noreferrer" 
              className="webcare-founder-link-item"
              title="Join Microsoft Teams live meeting or direct chat"
            >
              <Users size={16} color="#6366f1" />
              <div>
                <strong>Microsoft Teams:</strong> Live Meeting
                <span className="webcare-chat-tag webcare-chat-tag-connect">Connect</span>
              </div>
            </a>
            <a 
              href={prebuiltWhatsappUrl} 
              target="_blank" 
              rel="noopener noreferrer" 
              className="webcare-founder-link-item"
              title={`WhatsApp chat with prebuilt message for ${siteName} (${domain || rawSiteUrl})`}
            >
              <Phone size={16} color="#16a34a" />
              <div>
                <strong>WhatsApp / Call:</strong> +880 1322 691090
                <span className="webcare-chat-tag">Chat Now</span>
              </div>
            </a>
            <a 
              href={prebuiltEmailUrl} 
              className="webcare-founder-link-item"
              title={`Direct email with prebuilt message for ${siteName} (${domain || rawSiteUrl})`}
            >
              <Mail size={16} color="#2563eb" />
              <div>
                <strong>Direct Email:</strong> hello@webcarepro.dev
                <span className="webcare-chat-tag">Send Inquiry</span>
              </div>
            </a>
          </div>
        </div>
      </div>

      {/* Services Section Header & Filters */}
      <div className="webcare-services-header">
        <div>
          <h2>
            <Wrench size={24} color="#3b82f6" />
            Professional Engineering Services
          </h2>
          <p>
            Explore specialized technical services designed to keep your WordPress sites secure, lightning-fast, and 99.99% available.
          </p>
        </div>

        {/* Filter Pills */}
        <div className="webcare-category-filters">
          {categories.map((cat) => (
            <button
              key={cat.id}
              className={`webcare-category-btn ${selectedCategory === cat.id ? 'active' : ''}`}
              onClick={() => setSelectedCategory(cat.id)}
            >
              {cat.label}
            </button>
          ))}
        </div>
      </div>

      {/* Services Catalog Grid */}
      <div className="webcare-services-grid">
        {filteredServices.map((service) => {
          const IconComponent = service.icon;
          return (
            <div key={service.id} className="webcare-service-card">
              <div className="webcare-service-card-top">
                <div className="webcare-service-icon-box">
                  <IconComponent size={24} />
                </div>
                <span 
                  className={`webcare-service-badge webcare-service-badge-${service.category}`}
                  style={{
                    color: service.badgeColor || '#2563eb',
                    backgroundColor: service.badgeBg || '#eff6ff'
                  }}
                >
                  {service.badge}
                </span>
              </div>

              <h3 className="webcare-service-title">{service.title}</h3>
              <p className="webcare-service-desc">{service.description}</p>

              <div className="webcare-service-features">
                {service.features.map((feature, idx) => (
                  <div key={idx} className="webcare-service-feature-item">
                    <CheckCircle2 size={16} className="webcare-check-icon" />
                    <span>{feature}</span>
                  </div>
                ))}
              </div>

              <div className="webcare-service-footer">
                <a
                  href={service.href}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="webcare-service-link"
                >
                  <span>Explore Service & Pricing</span>
                  <ArrowRight size={15} />
                </a>
              </div>
            </div>
          );
        })}
      </div>

      {/* Why Choose WebCare Pro - Value Pillars */}
      <div className="webcare-pillars-section">
        <h2 className="webcare-pillars-title">Why Businesses Rely On WebCare Pro</h2>
        <div className="webcare-pillars-grid">
          <div className="webcare-pillar-card">
            <div className="webcare-pillar-icon-box webcare-pillar-icon-blue">
              <ShieldCheck size={26} />
            </div>
            <h4>Senior SysAdmin Direct Access</h4>
            <p>
              Direct communication with senior engineer Mir Alamin. Zero ticketing red tape, no account reps, and zero guesswork.
            </p>
          </div>

          <div className="webcare-pillar-card">
            <div className="webcare-pillar-icon-box webcare-pillar-icon-red">
              <Clock size={26} />
            </div>
            <h4>15-Minute Emergency SLA</h4>
            <p>
              When your site is down or infected, seconds matter. Initial diagnostic triage begins within 15 minutes to restore uptime.
            </p>
          </div>

          <div className="webcare-pillar-card">
            <div className="webcare-pillar-icon-box webcare-pillar-icon-green">
              <Lock size={26} />
            </div>
            <h4>No Lock-in Contracts</h4>
            <p>
              Transparent fixed-rate emergency interventions or flexible monthly maintenance retainers you can cancel anytime.
            </p>
          </div>

          <div className="webcare-pillar-card">
            <div className="webcare-pillar-icon-box webcare-pillar-icon-amber">
              <Star size={26} />
            </div>
            <h4>100% Proven Track Record</h4>
            <p>
              Over 680 successfully completed projects with a perfect 100% Job Success Score and 5-star client ratings worldwide.
            </p>
          </div>
        </div>
      </div>

      {/* Emergency Contact & Call To Action Banner */}
      <div className="webcare-contact-cta">
        <div className="webcare-contact-cta-left">
          <div className="webcare-contact-badge">
            <Activity size={16} /> 24/7 Global Availability
          </div>
          <h3>Need Help With Your WordPress Site or Server?</h3>
          <p>
            Whether you are experiencing an active malware infection, slow page load speeds, server gateway errors,
            or need reliable monthly maintenance, WebCare Pro is ready to assist.
          </p>

          <div className="webcare-contact-methods">
            <a 
              href={prebuiltEmailUrl}
              className="webcare-contact-item webcare-contact-item-link"
              title={`Click to send email with prebuilt message for ${siteName} (${domain || rawSiteUrl})`}
            >
              <Mail size={16} />
              <span>hello@webcarepro.dev</span>
            </a>
            <a 
              href={prebuiltWhatsappUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="webcare-contact-item webcare-contact-item-link"
              title={`Click to open WhatsApp chat with prebuilt message for ${siteName} (${domain || rawSiteUrl})`}
            >
              <Phone size={16} />
              <span>+880 1322 691090 (WhatsApp)</span>
            </a>
            <a 
              href={TEAMS_INVITE_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="webcare-contact-item webcare-contact-item-link"
              title="Connect via Microsoft Teams live meeting"
            >
              <Users size={16} />
              <span>Microsoft Teams</span>
            </a>
            <a 
              href={UPWORK_PROFILE_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="webcare-contact-item webcare-contact-item-link"
              title="View Upwork Top Rated Plus profile"
            >
              <Star size={16} />
              <span>Upwork Profile</span>
            </a>
            <a 
              href="https://webcarepro.dev"
              target="_blank"
              rel="noopener noreferrer"
              className="webcare-contact-item webcare-contact-item-link"
            >
              <Globe size={16} />
              <span>https://webcarepro.dev</span>
            </a>
          </div>
        </div>

        <div className="webcare-contact-cta-right">
          <a
            href={prebuiltWhatsappUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="webcare-btn webcare-btn-whatsapp"
            style={{ justifyContent: 'center' }}
          >
            <MessageSquare size={16} />
            <span>Chat Directly on WhatsApp</span>
          </a>
          <a
            href={TEAMS_INVITE_URL}
            target="_blank"
            rel="noopener noreferrer"
            className="webcare-btn webcare-btn-teams"
            style={{ justifyContent: 'center' }}
          >
            <Users size={16} />
            <span>Join on Microsoft Teams</span>
          </a>
          <a
            href="https://webcarepro.dev/contact"
            target="_blank"
            rel="noopener noreferrer"
            className="webcare-btn webcare-btn-cta-primary"
          >
            <span>Request Consultation or Quote</span>
            <ExternalLink size={16} />
          </a>
          <div className="webcare-cta-guarantee">
            <CheckCircle2 size={14} color="#10b981" />
            <span>Guaranteed Confidentiality & NDA Protected</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AboutServicesPage;
