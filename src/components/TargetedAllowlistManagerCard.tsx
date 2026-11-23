import React, { useState } from 'react';
import {
  Globe,
  Plus,
  Trash2,
  Edit2,
  Check,
  X,
  Shield,
  Radio,
  Server,
  Layers,
  HelpCircle,
  Sparkles,
  AlertCircle
} from 'lucide-react';

export interface TargetedAllowlistRule {
  id: string;
  name: string;
  enabled: boolean;
  user_agents: string[];
  endpoints: string[];
  ip_addresses: string[];
  hostnames?: string[];
  asns?: string[];
  required_headers?: string[];
  methods: string[];
  log_payload?: boolean;
  description?: string;
}

interface TargetedAllowlistManagerCardProps {
  rulesJson: string;
  onChange: (newJson: string) => void;
  onSave: (rulesJson: string) => void;
  isSaving: boolean;
  isSaved: boolean;
  activePluginSlugs?: string[];
}

export interface PresetTemplate {
  name: string;
  badge: string;
  category: 'E-Commerce' | 'Payments' | 'Shipping' | 'Marketing & CRM' | 'Membership & LMS' | 'Automation';
  plugin_slugs?: string[];
  plugin_name?: string;
  rule: Omit<TargetedAllowlistRule, 'id'>;
}

export const PRESET_TEMPLATES: PresetTemplate[] = [
  // --- E-COMMERCE & STORE APPS ---
  {
    name: 'WooCommerce Mobile App',
    badge: 'Woo App',
    category: 'E-Commerce',
    plugin_slugs: ['woocommerce'],
    plugin_name: 'WooCommerce',
    rule: {
      name: 'WooCommerce Mobile App (iOS / Android)',
      enabled: true,
      user_agents: ['WooCommerce/*', 'wc-ios/*', 'wc-android/*', 'Jetpack by WordPress.com*'],
      endpoints: ['/wp-json/wc/v3/*', '/wp-json/wc-analytics/*', '/xmlrpc.php*'],
      ip_addresses: [
        '192.0.64.0/18',
        '192.0.80.0/20',
        '192.0.96.0/20',
        '192.0.112.0/20',
        '195.234.108.0/22',
        '122.248.245.244/32',
        '54.217.201.243/32',
        '54.232.116.4/32'
      ],
      hostnames: ['wordpress.com', 'jetpack.com'],
      asns: ['AS2635'],
      methods: ['GET', 'POST', 'PUT', 'DELETE'],
      log_payload: true,
      description: 'Allows store owners and managers using official WooCommerce Mobile app to manage catalog and fulfill orders via Automattic Jetpack sync (AS2635).'
    }
  },
  {
    name: 'WooCommerce POS (Point of Sale)',
    badge: 'Woo POS',
    category: 'E-Commerce',
    plugin_slugs: ['woocommerce', 'woocommerce-pos', 'foosales-for-woocommerce'],
    plugin_name: 'WooCommerce POS',
    rule: {
      name: 'WooCommerce POS In-Store Terminals',
      enabled: true,
      user_agents: ['*WooCommerce-POS*', '*wc-pos*', '*Oliver POS*', '*FooSales*'],
      endpoints: ['/wp-json/wc/v3/orders*', '/wp-json/wc/v3/products*', '/wp-json/wc-pos/*'],
      ip_addresses: [],
      methods: ['GET', 'POST', 'PUT'],
      log_payload: true,
      description: 'Permits in-store physical POS terminals and barcode scanners to sync order and product state.'
    }
  },
  {
    name: 'Shopify Multichannel Sync',
    badge: 'Shopify Sync',
    category: 'E-Commerce',
    plugin_slugs: ['shopify', 'shopify-ecommerce-shopping-cart', 'cartrover'],
    plugin_name: 'Shopify / Multichannel',
    rule: {
      name: 'Shopify Store Multichannel Inventory Sync',
      enabled: true,
      user_agents: ['Shopify/*', '*Shopify-Webhook*', '*CartRover*', '*Shopify-Captain-Hook*'],
      endpoints: ['/wp-json/wc/v3/products*', '/wp-json/wc/v3/orders*'],
      ip_addresses: [],
      hostnames: ['myshopify.com', 'shopify.com'],
      asns: ['AS62679'],
      required_headers: ['X-Shopify-Hmac-Sha256'],
      methods: ['GET', 'POST', 'PUT'],
      log_payload: true,
      description: 'Allows Shopify inventory connector apps and CartRover to bridge orders. Verified via Shopify ASN (AS62679) & cryptographic X-Shopify-Hmac-Sha256 header.'
    }
  },
  {
    name: 'TikTok Shop Connector',
    badge: 'TikTok Shop',
    category: 'E-Commerce',
    plugin_slugs: ['tiktok-for-woocommerce', 'tiktok'],
    plugin_name: 'TikTok for WooCommerce',
    rule: {
      name: 'TikTok Shop for WooCommerce Connector',
      enabled: true,
      user_agents: ['*TikTokShop*', '*TikTok-Api*', '*ByteDance*', '*Bytespider*'],
      endpoints: ['/wp-json/tiktok/v1/*', '/wp-json/wc/v3/orders*'],
      ip_addresses: [],
      hostnames: ['tiktokglobalshop.com', 'tiktokv.com'],
      asns: ['AS396986', 'AS138699'],
      methods: ['GET', 'POST', 'PUT'],
      log_payload: true,
      description: 'Allows TikTok Shop integration workers to sync live catalog items and receive in-feed purchase orders (ByteDance AS396986/AS138699).'
    }
  },
  {
    name: 'Google & YouTube for WooCommerce',
    badge: 'Google Shopping',
    category: 'E-Commerce',
    plugin_slugs: ['google-listings-and-ads', 'google-for-woocommerce'],
    plugin_name: 'Google Listings & Ads',
    rule: {
      name: 'Google Merchant Center & YouTube Shopping',
      enabled: true,
      user_agents: ['*Google-Wp-Plugin*', '*Google-Shopping*', '*Googlebot*', '*Storebot-Google*'],
      endpoints: ['/wp-json/google-for-woocommerce/*', '/wp-json/wc/v3/products*'],
      ip_addresses: ['66.249.64.0/19'],
      hostnames: ['googlebot.com', 'google.com'],
      asns: ['AS15169'],
      methods: ['GET', 'POST'],
      log_payload: true,
      description: 'Permits Google Merchant Center & YouTube Shopping to crawl product inventory. Verified by Google rDNS (*.googlebot.com, *.google.com) and AS15169.'
    }
  },
  {
    name: 'Pinterest for WooCommerce',
    badge: 'Pinterest',
    category: 'E-Commerce',
    plugin_slugs: ['pinterest-for-woocommerce'],
    plugin_name: 'Pinterest for WooCommerce',
    rule: {
      name: 'Pinterest Business Catalog Feed',
      enabled: true,
      user_agents: ['*Pinterest/*', '*Pinterest-Catalog*', '*Pinterestbot*'],
      endpoints: ['/wp-json/pinterest/v1/*', '/wp-json/wc/v3/products*'],
      ip_addresses: ['54.236.1.0/24'],
      hostnames: ['pinterest.com'],
      methods: ['GET', 'POST'],
      log_payload: true,
      description: 'Enables Pinterest product catalog synchronization and visual tag event reporting via Pinterest crawler subnet (54.236.1.0/24) & rDNS (*.pinterest.com).'
    }
  },
  {
    name: 'Facebook & Instagram for WooCommerce',
    badge: 'Meta / Insta',
    category: 'E-Commerce',
    plugin_slugs: ['facebook-for-woocommerce'],
    plugin_name: 'Facebook for WooCommerce',
    rule: {
      name: 'Meta Facebook & Instagram Store Sync',
      enabled: true,
      user_agents: ['*facebookexternalhit*', '*Facebot*', '*Meta-Api*', '*meta-externalagent*'],
      endpoints: ['/wp-json/wc-facebook/v1/*', '/wp-json/wc/v3/products*'],
      ip_addresses: ['31.13.24.0/21', '66.220.144.0/20', '69.63.176.0/20', '69.171.224.0/19', '173.252.64.0/18'],
      hostnames: ['fbsv.net', 'facebook.com'],
      asns: ['AS32934'],
      methods: ['GET', 'POST'],
      log_payload: true,
      description: 'Synchronizes WooCommerce catalog with Facebook Commerce Manager and Instagram Shop (Meta AS32934 & *.fbsv.net rDNS).'
    }
  },

  // --- PAYMENTS & GATEWAY WEBHOOKS ---
  {
    name: 'Stripe Webhooks & IPN',
    badge: 'Stripe',
    category: 'Payments',
    plugin_slugs: ['woocommerce-gateway-stripe', 'stripe', 'payment-gateway-stripe-and-woocommerce-integration'],
    plugin_name: 'Stripe for WooCommerce',
    rule: {
      name: 'Stripe Payment Gateway Webhook Listener',
      enabled: true,
      user_agents: ['Stripe/*', '*Stripe-Webhook*'],
      endpoints: ['/?wc-api=wc_stripe*', '/wp-json/stripe/*', '/wc-api/WC_Stripe*'],
      ip_addresses: [
        '3.18.12.63',
        '3.69.109.8',
        '3.120.168.93',
        '3.130.192.231',
        '13.235.14.237',
        '13.235.122.149',
        '18.211.135.69',
        '35.154.171.200',
        '35.157.207.129',
        '52.15.183.38',
        '54.88.130.119',
        '54.88.130.237',
        '54.187.174.169',
        '54.187.205.235',
        '54.187.216.72'
      ],
      hostnames: ['stripe.com'],
      required_headers: ['Stripe-Signature'],
      methods: ['POST'],
      log_payload: true,
      description: 'Official Stripe Webhook IPs + Stripe-Signature header. Protects automated asynchronous charge and subscription lifecycle delivery.'
    }
  },
  {
    name: 'PayPal IPN & REST Webhooks',
    badge: 'PayPal',
    category: 'Payments',
    plugin_slugs: ['woocommerce-paypal-payments', 'paypal-for-woocommerce'],
    plugin_name: 'PayPal Payments',
    rule: {
      name: 'PayPal IPN & Commerce Platform Webhooks',
      enabled: true,
      user_agents: ['PayPal IPN*', '*PayPal-Webhook*'],
      endpoints: ['/?wc-api=WC_Gateway_Paypal*', '/wp-json/woocommerce-paypal-payments/v1/*'],
      ip_addresses: [
        '64.4.240.0/21',
        '64.4.248.0/22',
        '66.211.168.0/22',
        '91.243.72.0/23',
        '173.0.80.0/20',
        '185.177.52.0/22',
        '192.160.215.0/24',
        '198.54.216.0/23'
      ],
      hostnames: ['paypal.com'],
      methods: ['POST', 'GET'],
      log_payload: true,
      description: 'Official PayPal server CIDR subnets & *.paypal.com rDNS. Guarantees PayPal IPN and webhook callbacks bypass WAF filters without timeout.'
    }
  },
  {
    name: 'Square Webhooks & POS',
    badge: 'Square',
    category: 'Payments',
    plugin_slugs: ['woocommerce-square'],
    plugin_name: 'WooCommerce Square',
    rule: {
      name: 'Square Payments & Inventory Sync',
      enabled: true,
      user_agents: ['*Square-Connect*', '*Square*'],
      endpoints: ['/wp-json/wc-square/v1/*', '/?wc-api=wc_square*'],
      ip_addresses: ['54.245.1.154/32', '34.202.99.168/32', '54.212.177.79/32', '107.20.218.8/32'],
      hostnames: ['squareup.com'],
      required_headers: ['x-square-hmacsha256-signature'],
      methods: ['POST', 'GET'],
      log_payload: true,
      description: 'Maintains live product catalog and payment synchronization with Square retail systems (verified via official IPs and x-square-hmacsha256-signature).'
    }
  },
  {
    name: 'Klarna Payments Webhooks',
    badge: 'Klarna',
    category: 'Payments',
    plugin_slugs: ['klarna-payments-for-woocommerce', 'klarna-checkout-for-woocommerce'],
    plugin_name: 'Klarna for WooCommerce',
    rule: {
      name: 'Klarna Checkout & Instant Order Push',
      enabled: true,
      user_agents: ['*Klarna*'],
      endpoints: ['/wc-api/wc_gateway_klarna_*', '/wp-json/kco/v1/*'],
      ip_addresses: [],
      hostnames: ['klarna.com', 'klarnaevt.com'],
      methods: ['POST'],
      log_payload: true,
      description: 'Permits Klarna BNPL (Buy Now Pay Later) verification callbacks and order validation signals (*.klarna.com, *.klarnaevt.com).'
    }
  },
  {
    name: 'Mollie Payments Webhooks',
    badge: 'Mollie',
    category: 'Payments',
    plugin_slugs: ['mollie-payments-for-woocommerce'],
    plugin_name: 'Mollie Payments for WooCommerce',
    rule: {
      name: 'Mollie Payments Webhook Callback',
      enabled: true,
      user_agents: ['*Mollie*'],
      endpoints: ['/?wc-api=wc_mollie_*', '/wp-json/mollie/v1/*'],
      ip_addresses: [
        '35.241.221.32',
        '34.76.165.178',
        '34.79.136.88',
        '34.77.244.49',
        '34.76.19.158',
        '34.141.200.14',
        '34.76.201.228',
        '34.76.188.130',
        '34.76.90.110',
        '34.77.104.206',
        '34.147.124.17',
        '34.90.54.196',
        '34.90.108.3',
        '35.234.168.245',
        '35.233.7.254',
        '34.90.69.164'
      ],
      hostnames: ['mollie.com'],
      methods: ['POST', 'GET'],
      log_payload: true,
      description: 'Official verified Mollie API egress IP addresses & *.mollie.com rDNS. Ensures Mollie iDEAL, SEPA, and card webhook notifications are processed smoothly.'
    }
  },
  {
    name: 'Authorize.Net Webhooks',
    badge: 'Authorize.Net',
    category: 'Payments',
    plugin_slugs: ['authorizenet-gateway-for-woocommerce', 'woocommerce-gateway-authorize-net-cim'],
    plugin_name: 'Authorize.Net for WooCommerce',
    rule: {
      name: 'Authorize.Net Silent Post & Webhooks',
      enabled: true,
      user_agents: ['*Authorize.Net*', '*AuthorizeNet*'],
      endpoints: ['/?wc-api=wc_gateway_authorizenet_*', '/wp-json/wc-authorizenet/v1/*'],
      ip_addresses: ['198.241.128.0/17', '198.241.206.38', '198.241.207.38', '198.241.206.96'],
      hostnames: ['authorize.net'],
      required_headers: ['X-ANET-Signature'],
      methods: ['POST'],
      log_payload: true,
      description: 'Authorizes silent post and webhook event dispatching for Authorize.Net merchant accounts (198.241.128.0/17 subnet & X-ANET-Signature).'
    }
  },
  {
    name: 'Adyen Webhook Notifications',
    badge: 'Adyen',
    category: 'Payments',
    plugin_slugs: ['adyen-payment-gateway', 'adyen-woocommerce-payments'],
    plugin_name: 'Adyen Payment Gateway',
    rule: {
      name: 'Adyen Global Payment Webhooks',
      enabled: true,
      user_agents: ['*Adyen*'],
      endpoints: ['/wp-json/adyen/v1/notification*', '/?wc-api=wc_gateway_adyen*'],
      ip_addresses: [
        '82.199.87.128/26',
        '82.199.90.136/29',
        '82.199.90.160/27',
        '213.52.172.0/25',
        '62.146.248.0/21',
        '85.184.228.0/22',
        '91.212.42.0/24',
        '135.84.148.0/22',
        '147.12.16.0/20',
        '185.101.196.0/22',
        '145.63.64.0/18'
      ],
      hostnames: ['adyen.com', 'adyenpayments.com'],
      methods: ['POST'],
      log_payload: true,
      description: 'Handles high-frequency global payment notifications from Adyen financial processing infrastructure across all 11 official CIDR blocks.'
    }
  },

  // --- SHIPPING & 3PL FULFILLMENT ---
  {
    name: 'ShipStation 3PL Sync',
    badge: 'ShipStation',
    category: 'Shipping',
    plugin_slugs: ['woocommerce-shipstation-integration'],
    plugin_name: 'WooCommerce ShipStation Integration',
    rule: {
      name: 'ShipStation 3PL Order & Tracking Sync',
      enabled: true,
      user_agents: ['ShipStation/*', '*ShipStation*'],
      endpoints: ['/?wc-api=wc_shipstation*', '/wp-json/wc/v3/orders*'],
      ip_addresses: [],
      hostnames: ['shipstation.com'],
      methods: ['GET', 'POST'],
      log_payload: true,
      description: 'Allows ShipStation shipping management software to pull awaiting orders and upload shipment tracking barcodes (*.shipstation.com).'
    }
  },
  {
    name: 'Shippo Shipping API',
    badge: 'Shippo',
    category: 'Shipping',
    plugin_slugs: ['shippo-for-woocommerce'],
    plugin_name: 'Shippo for WooCommerce',
    rule: {
      name: 'Shippo Shipping Rate & Label Push',
      enabled: true,
      user_agents: ['Shippo/*', '*Shippo*'],
      endpoints: ['/wp-json/shippo/v1/*', '/wp-json/wc/v3/orders*'],
      ip_addresses: [],
      hostnames: ['goshippo.com'],
      methods: ['GET', 'POST'],
      log_payload: true,
      description: 'Enables Shippo rate calculation, shipping label creation, and return tracking push.'
    }
  },
  {
    name: 'Printful On-Demand Fulfillment',
    badge: 'Printful',
    category: 'Shipping',
    plugin_slugs: ['printful-shipping-for-woocommerce'],
    plugin_name: 'Printful for WooCommerce',
    rule: {
      name: 'Printful Print-on-Demand Orders & Stock',
      enabled: true,
      user_agents: ['*Printful*', 'Printful-Webhooks/*', 'Printful-Webhook'],
      endpoints: ['/wp-json/printful/v1/*', '/wp-json/wc/v3/orders*'],
      ip_addresses: [],
      hostnames: ['printful.com'],
      methods: ['GET', 'POST', 'PUT'],
      log_payload: true,
      description: 'Connects Printful print-on-demand fulfillment centers to automatically receive order line items.'
    }
  },
  {
    name: 'Printify On-Demand Fulfillment',
    badge: 'Printify',
    category: 'Shipping',
    plugin_slugs: ['printify-for-woocommerce'],
    plugin_name: 'Printify for WooCommerce',
    rule: {
      name: 'Printify On-Demand Order Webhooks',
      enabled: true,
      user_agents: ['*Printify*'],
      endpoints: ['/wp-json/printify/v1/*', '/wp-json/wc/v3/orders*'],
      ip_addresses: [],
      hostnames: ['printify.com'],
      required_headers: ['X-Printify-Webhook-Signature'],
      methods: ['GET', 'POST'],
      log_payload: true,
      description: 'Allows Printify factory network to publish product variants and update fulfillment status (verified via X-Printify-Webhook-Signature).'
    }
  },
  {
    name: 'Deliverr / Flexport 3PL',
    badge: 'Flexport',
    category: 'Shipping',
    plugin_slugs: ['deliverr', 'flexport'],
    plugin_name: 'Flexport / Deliverr',
    rule: {
      name: 'Flexport / Deliverr Multichannel 3PL',
      enabled: true,
      user_agents: ['*Deliverr*', '*Flexport*'],
      endpoints: ['/wp-json/wc/v3/orders*', '/wp-json/wc/v3/products*'],
      ip_addresses: [],
      hostnames: ['flexport.com'],
      required_headers: ['X-Flexport-Signature'],
      methods: ['GET', 'POST', 'PUT'],
      log_payload: true,
      description: 'Integrates Flexport 2-day fast shipping warehouse network with WooCommerce store orders (verified via X-Flexport-Signature).'
    }
  },

  // --- MARKETING, REVIEWS & CRM ---
  {
    name: 'Klaviyo WooCommerce Integration',
    badge: 'Klaviyo',
    category: 'Marketing & CRM',
    plugin_slugs: ['klaviyo'],
    plugin_name: 'Klaviyo',
    rule: {
      name: 'Klaviyo WooCommerce Orders & Catalog Sync',
      enabled: true,
      user_agents: ['*Klaviyo*', 'EFS-IS2-WooCommerce/*', 'Klaviyo/1.0*'],
      endpoints: [
        '/wp-json/wc/v2/orders/*',
        '/wp-json/wc/v3/orders/*',
        '/wp-json/wc/v3/products/*'
      ],
      ip_addresses: [],
      hostnames: ['klaviyo.com'],
      methods: ['ALL'],
      log_payload: true,
      description: 'Permits Klaviyo background workers to sync customer order histories and catalog updates without rate limit blocks (Klaviyo/1.0 User-Agent).'
    }
  },
  {
    name: 'Mailchimp for WooCommerce',
    badge: 'Mailchimp',
    category: 'Marketing & CRM',
    plugin_slugs: ['mailchimp-for-woocommerce'],
    plugin_name: 'Mailchimp for WooCommerce',
    rule: {
      name: 'Mailchimp E-Commerce Sync & Cart Recovery',
      enabled: true,
      user_agents: ['*MailChimp.com*', '*Mailchimp*'],
      endpoints: ['/wp-json/mailchimp-for-woocommerce/*', '/wp-json/wc/v3/orders*'],
      ip_addresses: [],
      hostnames: ['mailchimp.com', 'mandrillapp.com'],
      asns: ['AS14782'],
      methods: ['GET', 'POST', 'PATCH'],
      log_payload: true,
      description: 'Transfers purchase history, customer lifetime value, and abandoned cart events to Mailchimp lists (Rocket Science Group AS14782).'
    }
  },
  {
    name: 'HubSpot for WooCommerce',
    badge: 'HubSpot',
    category: 'Marketing & CRM',
    plugin_slugs: ['makewebbetter-hubspot-for-woocommerce', 'leadin'],
    plugin_name: 'HubSpot for WooCommerce',
    rule: {
      name: 'HubSpot CRM Customer & Deal Ingestion',
      enabled: true,
      user_agents: ['HubSpot/*', '*HubSpot*'],
      endpoints: ['/wp-json/hubspot/v1/*', '/wp-json/wc/v3/customers*'],
      ip_addresses: ['199.60.103.0/24', '143.244.80.0/20', '54.174.52.32/27'],
      hostnames: ['hubapi.com', 'hubspot.com'],
      required_headers: ['X-HubSpot-Signature-v3'],
      methods: ['GET', 'POST'],
      log_payload: true,
      description: 'Permits HubSpot cloud marketing and sales pipeline to synchronize WooCommerce customer CRM records via official subnets & X-HubSpot-Signature-v3.'
    }
  },
  {
    name: 'ActiveCampaign WooCommerce Sync',
    badge: 'ActiveCampaign',
    category: 'Marketing & CRM',
    plugin_slugs: ['activecampaign-for-woocommerce', 'activecampaign-subscription-forms'],
    plugin_name: 'ActiveCampaign',
    rule: {
      name: 'ActiveCampaign Deep Data E-Commerce Sync',
      enabled: true,
      user_agents: ['*ActiveCampaign*'],
      endpoints: ['/wp-json/activecampaign/v1/*', '/wp-json/wc/v3/orders*'],
      ip_addresses: ['173.193.204.224/27', '192.99.45.184/29', '52.1.123.163/32', '52.71.102.219/32', '52.86.188.149/32'],
      hostnames: ['activehosted.com', 'api-us1.com'],
      methods: ['GET', 'POST'],
      log_payload: true,
      description: 'Synchronizes contact tags, custom fields, and order revenue directly into ActiveCampaign automations via official outbound subnets.'
    }
  },
  {
    name: 'Omnisend E-Commerce Marketing',
    badge: 'Omnisend',
    category: 'Marketing & CRM',
    plugin_slugs: ['omnisend-connect'],
    plugin_name: 'Omnisend for WooCommerce',
    rule: {
      name: 'Omnisend SMS & Email Marketing Webhooks',
      enabled: true,
      user_agents: ['*Omnisend*'],
      endpoints: ['/wp-json/omnisend/v1/*', '/wp-json/wc/v3/orders*'],
      ip_addresses: [],
      hostnames: ['omnisend.com'],
      methods: ['GET', 'POST'],
      log_payload: true,
      description: 'Powers Omnisend SMS tracking, abandoned checkout SMS reminders, and order confirmations.'
    }
  },
  {
    name: 'Trustpilot Product Reviews',
    badge: 'Trustpilot',
    category: 'Marketing & CRM',
    plugin_slugs: ['trustpilot-reviews'],
    plugin_name: 'Trustpilot Reviews',
    rule: {
      name: 'Trustpilot Review Invitation Dispatcher',
      enabled: true,
      user_agents: ['*Trustpilot*'],
      endpoints: ['/wp-json/trustpilot/v1/*', '/wp-json/wc/v3/orders*'],
      ip_addresses: [],
      hostnames: ['trustpilot.com'],
      methods: ['GET', 'POST'],
      log_payload: true,
      description: 'Triggers automated review invitation emails via Trustpilot API following successful order delivery.'
    }
  },
  {
    name: 'Yotpo Reviews & Loyalty',
    badge: 'Yotpo',
    category: 'Marketing & CRM',
    plugin_slugs: ['yotpo-social-reviews-for-woocommerce'],
    plugin_name: 'Yotpo Reviews',
    rule: {
      name: 'Yotpo Reviews, Loyalty & Referrals',
      enabled: true,
      user_agents: ['*Yotpo*'],
      endpoints: ['/wp-json/yotpo/v1/*', '/wp-json/wc/v3/products*'],
      ip_addresses: [],
      hostnames: ['yotpo.com', 'swellrewards.com'],
      methods: ['GET', 'POST'],
      log_payload: true,
      description: 'Maintains verified buyer review stars, loyalty points, and referral discount sync.'
    }
  },

  // --- MEMBERSHIP, SUBSCRIPTIONS & LMS ---
  {
    name: 'WooCommerce Subscriptions Engine',
    badge: 'Woo Subscriptions',
    category: 'Membership & LMS',
    plugin_slugs: ['woocommerce-subscriptions'],
    plugin_name: 'WooCommerce Subscriptions',
    rule: {
      name: 'WooCommerce Subscriptions & Renewal Workers',
      enabled: true,
      user_agents: ['*WooCommerce-Subscriptions*', '*WCS-Worker*'],
      endpoints: ['/wp-json/wc/v1/subscriptions*', '/wp-json/wc/v3/subscriptions*'],
      ip_addresses: [],
      hostnames: ['woocommerce.com'],
      methods: ['ALL'],
      log_payload: true,
      description: 'Allows background subscription renewal engines and external recurring billing workers to process renewal payments.'
    }
  },
  {
    name: 'MemberPress Membership Engine',
    badge: 'MemberPress',
    category: 'Membership & LMS',
    plugin_slugs: ['memberpress'],
    plugin_name: 'MemberPress',
    rule: {
      name: 'MemberPress Developer Tools & Webhooks',
      enabled: true,
      user_agents: ['*MemberPress*', '*MP-Webhook*'],
      endpoints: ['/wp-json/mp/v1/*', '/?memberpress_webhook*'],
      ip_addresses: [],
      hostnames: ['memberpress.com'],
      methods: ['GET', 'POST', 'PUT'],
      log_payload: true,
      description: 'Guarantees external membership management systems, mobile companion apps, and CRM hooks pass freely.'
    }
  },
  {
    name: 'LearnDash LMS REST API',
    badge: 'LearnDash',
    category: 'Membership & LMS',
    plugin_slugs: ['sfwd-lms'],
    plugin_name: 'LearnDash LMS',
    rule: {
      name: 'LearnDash LMS Course & Student Enrollment',
      enabled: true,
      user_agents: ['*LearnDash*', '*ld-app*', '*LearnDash-Mobile*'],
      endpoints: ['/wp-json/ldlms/v2/*', '/wp-json/ldlms/v1/*'],
      ip_addresses: [],
      hostnames: ['learndash.com'],
      methods: ['GET', 'POST', 'PUT'],
      log_payload: true,
      description: 'Supports LearnDash native mobile apps, grading tools, and external SCORM student progress tracking.'
    }
  },
  {
    name: 'Tutor LMS Student Portal',
    badge: 'Tutor LMS',
    category: 'Membership & LMS',
    plugin_slugs: ['tutor'],
    plugin_name: 'Tutor LMS',
    rule: {
      name: 'Tutor LMS Mobile & Quiz Sync',
      enabled: true,
      user_agents: ['*TutorLMS*', '*tutor-mobile*'],
      endpoints: ['/wp-json/tutor/v1/*'],
      ip_addresses: [],
      hostnames: ['themeum.com'],
      methods: ['GET', 'POST'],
      log_payload: true,
      description: 'Permits Tutor LMS mobile applications to submit lesson progress, quiz answers, and certificates.'
    }
  },

  // --- AUTOMATION & INTEGRATION HUBS ---
  {
    name: 'Make (Integromat) Automation',
    badge: 'Make (Integromat)',
    category: 'Automation',
    plugin_slugs: ['integromat'],
    plugin_name: 'Make / Integromat',
    rule: {
      name: 'Make (Integromat) Cloud Automation Webhooks',
      enabled: true,
      user_agents: ['Make/*', '*Integromat*'],
      endpoints: ['/wp-json/wc/v3/orders*', '/wp-json/wc/v3/customers*', '/wp-json/wp/v2/posts*'],
      ip_addresses: [
        '54.209.79.175',
        '54.80.47.193',
        '54.161.178.114',
        '44.209.150.16',
        '44.210.162.163',
        '35.170.163.230',
        '54.75.157.176',
        '54.78.149.203',
        '52.18.144.195',
        '34.254.1.9',
        '52.31.156.93',
        '52.50.32.186'
      ],
      hostnames: ['make.com'],
      methods: ['GET', 'POST', 'PUT'],
      log_payload: true,
      description: 'Official verified static IP ranges for Make (Integromat) US1, US2, EU1, and EU2 cloud execution clusters.'
    }
  },
  {
    name: 'Zapier Automation',
    badge: 'Zapier',
    category: 'Automation',
    plugin_slugs: ['zapier'],
    plugin_name: 'Zapier',
    rule: {
      name: 'Zapier Multi-App Cloud Automation',
      enabled: true,
      user_agents: ['Zapier', 'Zapier/*'],
      endpoints: ['/wp-json/wc/v3/orders*', '/wp-json/wc/v3/customers*', '/wp-json/wp/v2/posts*'],
      ip_addresses: [],
      hostnames: ['zapier.com'],
      methods: ['GET', 'POST', 'PUT'],
      log_payload: true,
      description: 'Allows Zapier cloud triggers to create, update, or poll orders and users safely (matched by Zapier User-Agent and endpoint).'
    }
  }
];

// Helper to evaluate security trust level of a rule
export const getRuleTrustTier = (rule: {
  ip_addresses?: string[];
  hostnames?: string[];
  asns?: string[];
  required_headers?: string[];
}): { label: string; level: 'high' | 'medium' | 'low'; desc: string } => {
  const hasIps = (rule.ip_addresses || []).filter(s => s.trim().length > 0).length > 0;
  const hasHostnames = (rule.hostnames || []).filter(s => s.trim().length > 0).length > 0;
  const hasHeaders = (rule.required_headers || []).filter(s => s.trim().length > 0).length > 0;
  const hasAsns = (rule.asns || []).filter(s => s.trim().length > 0).length > 0;

  if (hasHeaders || hasIps || hasHostnames) {
    return {
      label: 'High Trust',
      level: 'high',
      desc: 'Verified via cryptographic signature header, static IP subnet, or two-way reverse DNS.'
    };
  }

  if (hasAsns) {
    return {
      label: 'Medium Trust',
      level: 'medium',
      desc: 'Scoped to authorized Autonomous System Number (ASN) cloud network.'
    };
  }

  return {
    label: 'Low Trust (Spoofable)',
    level: 'low',
    desc: 'Unconstrained network access. Any client forging the User-Agent header can match this rule.'
  };
};

export const TargetedAllowlistManagerCard: React.FC<TargetedAllowlistManagerCardProps> = ({
  rulesJson,
  onChange,
  onSave,
  isSaving,
  isSaved,
  activePluginSlugs = []
}) => {
  // Parse current rules safely
  let rules: TargetedAllowlistRule[] = [];
  try {
    const parsed = typeof rulesJson === 'string' ? JSON.parse(rulesJson || '[]') : rulesJson;
    if (Array.isArray(parsed)) {
      rules = parsed;
    }
  } catch (e) {
    rules = [];
  }

  // Modal / Form state
  const [modalOpen, setModalOpen] = useState<boolean>(false);
  const [editingRuleId, setEditingRuleId] = useState<string | null>(null);
  const [selectedPresetCategory, setSelectedPresetCategory] = useState<string>('All');
  const [confirmDeleteRuleId, setConfirmDeleteRuleId] = useState<string | null>(null);

  // Form Fields
  const [formName, setFormName] = useState<string>('');
  const [formUas, setFormUas] = useState<string>('');
  const [formEndpoints, setFormEndpoints] = useState<string>('');
  const [formIps, setFormIps] = useState<string>('');
  const [formHostnames, setFormHostnames] = useState<string>('');
  const [formAsns, setFormAsns] = useState<string>('');
  const [formHeaders, setFormHeaders] = useState<string>('');
  const [formMethods, setFormMethods] = useState<string[]>(['ALL']);
  const [formDesc, setFormDesc] = useState<string>('');
  const [formLogPayload, setFormLogPayload] = useState<boolean>(true);
  const [formError, setFormError] = useState<string | null>(null);

  const openAddModal = () => {
    setEditingRuleId(null);
    setFormName('');
    setFormUas('');
    setFormEndpoints('');
    setFormIps('');
    setFormHostnames('');
    setFormAsns('');
    setFormHeaders('');
    setFormMethods(['ALL']);
    setFormDesc('');
    setFormLogPayload(true);
    setFormError(null);
    setModalOpen(true);
  };

  const openEditModal = (rule: TargetedAllowlistRule) => {
    setEditingRuleId(rule.id);
    setFormName(rule.name);
    setFormUas(rule.user_agents.join('\n'));
    setFormEndpoints(rule.endpoints.join('\n'));
    setFormIps((rule.ip_addresses || []).join('\n'));
    setFormHostnames((rule.hostnames || []).join('\n'));
    setFormAsns((rule.asns || []).join('\n'));
    setFormHeaders((rule.required_headers || []).join('\n'));
    setFormMethods(rule.methods || ['ALL']);
    setFormDesc(rule.description || '');
    setFormLogPayload(rule.log_payload !== false);
    setFormError(null);
    setModalOpen(true);
  };

  const applyPreset = (preset: typeof PRESET_TEMPLATES[0]) => {
    setEditingRuleId(null);
    setFormName(preset.rule.name);
    setFormUas(preset.rule.user_agents.join('\n'));
    setFormEndpoints(preset.rule.endpoints.join('\n'));
    setFormIps((preset.rule.ip_addresses || []).join('\n'));
    setFormHostnames((preset.rule.hostnames || []).join('\n'));
    setFormAsns((preset.rule.asns || []).join('\n'));
    setFormHeaders((preset.rule.required_headers || []).join('\n'));
    setFormMethods(preset.rule.methods || ['ALL']);
    setFormDesc(preset.rule.description || '');
    setFormLogPayload(preset.rule.log_payload !== false);
    setFormError(null);
    setModalOpen(true);
  };

  const handleSaveModal = () => {
    if (!formName.trim()) {
      setFormError('Please enter a descriptive Rule Name.');
      return;
    }

    const uas = formUas
      .split('\n')
      .map(s => s.trim())
      .filter(Boolean);

    const endpoints = formEndpoints
      .split('\n')
      .map(s => s.trim())
      .filter(Boolean);

    if (uas.length === 0 && endpoints.length === 0) {
      setFormError('Please provide at least one User-Agent or one Target Endpoint.');
      return;
    }

    const ips = formIps
      .split('\n')
      .map(s => s.trim())
      .filter(Boolean);

    const hostnames = formHostnames
      .split('\n')
      .map(s => s.trim())
      .filter(Boolean);

    const asns = formAsns
      .split('\n')
      .map(s => s.trim())
      .filter(Boolean);

    const headers = formHeaders
      .split('\n')
      .map(s => s.trim())
      .filter(Boolean);

    const updatedRule: TargetedAllowlistRule = {
      id: editingRuleId || `rule_${Date.now().toString(36)}_${Math.random().toString(36).substring(2, 6)}`,
      name: formName.trim(),
      enabled: true,
      user_agents: uas,
      endpoints: endpoints,
      ip_addresses: ips,
      hostnames: hostnames,
      asns: asns,
      required_headers: headers,
      methods: formMethods.length > 0 ? formMethods : ['ALL'],
      log_payload: formLogPayload,
      description: formDesc.trim()
    };

    let newRules: TargetedAllowlistRule[];
    if (editingRuleId) {
      newRules = rules.map(r => (r.id === editingRuleId ? updatedRule : r));
    } else {
      newRules = [...rules, updatedRule];
    }

    const jsonStr = JSON.stringify(newRules);
    onChange(jsonStr);
    onSave(jsonStr);
    setModalOpen(false);
  };

  const handleToggleRule = (ruleId: string) => {
    const newRules = rules.map(r => (r.id === ruleId ? { ...r, enabled: !r.enabled } : r));
    const jsonStr = JSON.stringify(newRules);
    onChange(jsonStr);
    onSave(jsonStr);
  };

  const handleDeleteRule = (ruleId: string) => {
    const newRules = rules.filter(r => r.id !== ruleId);
    const jsonStr = JSON.stringify(newRules);
    onChange(jsonStr);
    onSave(jsonStr);
    setConfirmDeleteRuleId(null);
  };

  const toggleMethod = (method: string) => {
    if (method === 'ALL') {
      setFormMethods(['ALL']);
      return;
    }
    let current = formMethods.filter(m => m !== 'ALL');
    if (current.includes(method)) {
      current = current.filter(m => m !== method);
    } else {
      current.push(method);
    }
    setFormMethods(current.length === 0 ? ['ALL'] : current);
  };

  return (
    <div className="webcare-firewall-card" style={{ padding: '20px', marginTop: '16px' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px', flexWrap: 'wrap', gap: '10px' }}>
        <div>
          <h3 className="webcare-firewall-section-title" style={{ fontSize: '16px', display: 'flex', alignItems: 'center', gap: '8px', margin: 0 }}>
            <Radio size={18} color="#4f46e5" /> Targeted Endpoint &amp; User-Agent Bypass Rules
          </h3>
          <p className="webcare-firewall-section-desc" style={{ marginTop: '4px', marginBottom: 0, fontSize: '12px', lineHeight: 1.4 }}>
            Zero-Trust access rules allowing specific client User-Agents (e.g. Klaviyo, Zapier) to access designated REST APIs or webhooks. All allowed requests are fully recorded in the WAF Logs with deep payload forensics.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <button
            type="button"
            className="webcare-btn"
            onClick={openAddModal}
            style={{
              background: '#4f46e5',
              color: '#ffffff',
              border: 'none',
              padding: '6px 14px',
              borderRadius: '6px',
              fontWeight: 600,
              fontSize: '12px',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px'
            }}
          >
            <Plus size={14} /> Add Targeted Rule
          </button>
        </div>
      </div>

      {/* Smart Detected Integrations Banner */}
      {(() => {
        // Find presets whose plugin_slugs match any activePluginSlugs
        const detectedPresets = PRESET_TEMPLATES.filter(p => {
          if (!p.plugin_slugs || p.plugin_slugs.length === 0) return false;
          return p.plugin_slugs.some(slug => activePluginSlugs.includes(slug));
        });

        // Helper to check if a preset is already represented in rules
        const isPresetAlreadyAdded = (p: typeof PRESET_TEMPLATES[0]) => {
          const pName = (p.name || '').toLowerCase();
          const pRuleName = (p.rule && p.rule.name ? p.rule.name : '').toLowerCase();
          const pPluginName = (p.plugin_name || '').toLowerCase();
          const pBadge = (p.badge || '').toLowerCase();

          return rules.some(r => {
            const rName = (r.name || '').toLowerCase();
            const rDesc = (r.description || '').toLowerCase();
            return (
              rName === pRuleName ||
              rName === pName ||
              (pName && rName.includes(pName)) ||
              (pRuleName && rName.includes(pRuleName)) ||
              (pPluginName && rName.includes(pPluginName)) ||
              (pBadge && rName.includes(pBadge)) ||
              (pName.includes('paypal') && (rName.includes('paypal') || rDesc.includes('paypal')))
            );
          });
        };

        // Filter out those already active in user's rules
        const unaddedPresets = detectedPresets.filter(p => !isPresetAlreadyAdded(p));

        if (unaddedPresets.length === 0) return null;

        const handleEnablePresetInstantly = (preset: typeof PRESET_TEMPLATES[0]) => {
          if (isPresetAlreadyAdded(preset)) return;

          const uniqueSlug = (preset.plugin_slugs && preset.plugin_slugs[0]) || preset.name.toLowerCase().replace(/[^a-z0-9]/g, '_');
          const newRule: TargetedAllowlistRule = {
            id: 'rule_' + uniqueSlug + '_' + Date.now().toString(36),
            name: preset.rule.name,
            enabled: true,
            user_agents: preset.rule.user_agents,
            endpoints: preset.rule.endpoints,
            ip_addresses: preset.rule.ip_addresses,
            hostnames: preset.rule.hostnames,
            asns: preset.rule.asns,
            required_headers: preset.rule.required_headers,
            methods: preset.rule.methods,
            log_payload: preset.rule.log_payload !== false,
            description: preset.rule.description
          };
          const newRules = [...rules, newRule];
          const jsonStr = JSON.stringify(newRules);
          onChange(jsonStr);
          onSave(jsonStr);
        };

        const handleEnableAllDetected = () => {
          const newlyAdded: TargetedAllowlistRule[] = [];
          unaddedPresets.forEach((p, idx) => {
            const alreadyInRules = [...rules, ...newlyAdded].some(r => {
              const rName = (r.name || '').toLowerCase();
              const rDesc = (r.description || '').toLowerCase();
              const pName = (p.name || '').toLowerCase();
              const pRuleName = (p.rule && p.rule.name ? p.rule.name : '').toLowerCase();
              const pPluginName = (p.plugin_name || '').toLowerCase();
              const pBadge = (p.badge || '').toLowerCase();

              return (
                rName === pRuleName ||
                rName === pName ||
                (pName && rName.includes(pName)) ||
                (pRuleName && rName.includes(pRuleName)) ||
                (pPluginName && rName.includes(pPluginName)) ||
                (pBadge && rName.includes(pBadge)) ||
                (pName.includes('paypal') && (rName.includes('paypal') || rDesc.includes('paypal')))
              );
            });

            if (!alreadyInRules) {
              const uniqueSlug = (p.plugin_slugs && p.plugin_slugs[0]) || p.name.toLowerCase().replace(/[^a-z0-9]/g, '_');
              newlyAdded.push({
                id: 'rule_' + uniqueSlug + '_' + (Date.now() + idx).toString(36),
                name: p.rule.name,
                enabled: true,
                user_agents: p.rule.user_agents,
                endpoints: p.rule.endpoints,
                ip_addresses: p.rule.ip_addresses,
                hostnames: p.rule.hostnames,
                asns: p.rule.asns,
                required_headers: p.rule.required_headers,
                methods: p.rule.methods,
                log_payload: p.rule.log_payload !== false,
                description: p.rule.description
              });
            }
          });

          if (newlyAdded.length === 0) return;

          const newRules = [...rules, ...newlyAdded];
          const jsonStr = JSON.stringify(newRules);
          onChange(jsonStr);
          onSave(jsonStr);
        };

        return (
          <div
            style={{
              padding: '14px 16px',
              borderRadius: '8px',
              background: 'linear-gradient(135deg, rgba(79, 70, 229, 0.08) 0%, rgba(16, 185, 129, 0.08) 100%)',
              border: '1px solid rgba(79, 70, 229, 0.3)',
              marginBottom: '16px',
              display: 'flex',
              alignItems: 'flex-start',
              justifyContent: 'space-between',
              gap: '12px',
              flexWrap: 'wrap'
            }}
          >
            <div style={{ flex: '1 1 300px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '7px', marginBottom: '4px' }}>
                <Sparkles size={16} color="#4f46e5" />
                <strong style={{ fontSize: '13px', color: 'var(--webcare-text-primary, #0f172a)' }}>
                  Detected Active Integrations ({unaddedPresets.length})
                </strong>
                <span className="webcare-badge-pill webcare-badge-clean" style={{ fontSize: '10px' }}>
                  Smart Recommendation
                </span>
              </div>
              <p style={{ margin: '0 0 10px 0', fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', lineHeight: 1.45 }}>
                We detected plugins installed on this WordPress site that communicate with external APIs and webhooks. You can enable pre-configured zero-trust firewall bypass rules with one click:
              </p>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                {unaddedPresets.map((preset, idx) => (
                  <button
                    key={idx}
                    type="button"
                    onClick={() => handleEnablePresetInstantly(preset)}
                    className="webcare-btn-micro webcare-preset-btn-detected"
                    title={`Click to enable "${preset.name}" rule now`}
                    style={{
                      fontWeight: 700,
                      fontSize: '11px',
                      padding: '4px 10px',
                      borderRadius: '5px',
                      cursor: 'pointer',
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '5px'
                    }}
                  >
                    <Check size={12} color="#10b981" />
                    <span>Enable {preset.plugin_name || preset.badge}</span>
                  </button>
                ))}
              </div>
            </div>

            <div style={{ alignSelf: 'center' }}>
              <button
                type="button"
                className="webcare-btn"
                onClick={handleEnableAllDetected}
                style={{
                  background: 'linear-gradient(135deg, #4f46e5 0%, #10b981 100%)',
                  color: '#ffffff',
                  border: 'none',
                  padding: '6px 14px',
                  borderRadius: '6px',
                  fontWeight: 700,
                  fontSize: '11px',
                  cursor: 'pointer',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                  boxShadow: '0 2px 4px rgba(79, 70, 229, 0.25)'
                }}
              >
                <Check size={13} /> Enable All Detected ({unaddedPresets.length})
              </button>
            </div>
          </div>
        );
      })()}

      {/* Quick Presets Bar with Category Filter */}
      <div style={{ padding: '12px 14px', background: 'var(--webcare-bg-surface, #f8fafc)', borderRadius: '8px', border: '1px solid var(--webcare-border-subtle, #e2e8f0)', marginBottom: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '8px', marginBottom: '10px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '11px', fontWeight: 700, color: 'var(--webcare-text-muted, #64748b)', textTransform: 'uppercase', display: 'inline-flex', alignItems: 'center', gap: '5px' }}>
              <Sparkles size={13} color="#4f46e5" /> Quick Presets ({PRESET_TEMPLATES.length} Verified Integration Templates):
            </span>
            <span style={{ fontSize: '10px', background: 'rgba(79, 70, 229, 0.08)', color: '#4f46e5', padding: '1px 6px', borderRadius: '4px', fontWeight: 600 }}>
              Verified: Oct 2026
            </span>
          </div>

          {/* Category Filter Pills */}
          <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
            {['All', 'E-Commerce', 'Payments', 'Shipping', 'Marketing & CRM', 'Membership & LMS', 'Automation'].map(cat => {
              const isCatActive = selectedPresetCategory === cat;
              return (
                <button
                  key={cat}
                  type="button"
                  className={`webcare-btn-micro ${isCatActive ? 'webcare-action-btn-clean' : ''}`}
                  onClick={() => setSelectedPresetCategory(cat)}
                  style={{
                    fontSize: '10px',
                    padding: '2px 8px',
                    fontWeight: 700,
                    borderRadius: '4px',
                    cursor: 'pointer',
                    ...(isCatActive ? { background: '#4f46e5', color: '#ffffff', borderColor: '#4338ca' } : {})
                  }}
                >
                  {cat}
                </button>
              );
            })}
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
          {PRESET_TEMPLATES
            .filter(p => selectedPresetCategory === 'All' || p.category === selectedPresetCategory)
            .map((preset, idx) => {
              const isDetectedOnSite = preset.plugin_slugs && preset.plugin_slugs.some(slug => activePluginSlugs.includes(slug));
              return (
                <button
                  key={idx}
                  type="button"
                  className={`webcare-btn-micro ${isDetectedOnSite ? 'webcare-preset-btn-detected' : ''}`}
                  onClick={() => applyPreset(preset)}
                  title={`${preset.name} (${preset.category})\nClick to load and customize this preset${isDetectedOnSite ? '\n(Plugin detected active on this site!)' : ''}`}
                  style={{
                    fontWeight: 600,
                    fontSize: '11px',
                    padding: '4px 9px',
                    borderRadius: '5px',
                    cursor: 'pointer',
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '4px'
                  }}
                >
                  <span style={{ color: isDetectedOnSite ? '#10b981' : '#4f46e5', fontWeight: 800 }}>+</span>
                  <span>{preset.badge}</span>
                  {isDetectedOnSite && (
                    <span className="webcare-preset-badge-detected">
                      Detected
                    </span>
                  )}
                </button>
              );
            })}
        </div>
      </div>

      {/* Rules List */}
      {rules.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '30px 20px', border: '1px dashed var(--webcare-border-subtle, #cbd5e1)', borderRadius: '8px', background: 'var(--webcare-bg-surface, #f8fafc)' }}>
          <Layers size={32} color="#94a3b8" style={{ margin: '0 auto 8px auto', display: 'block' }} />
          <strong style={{ display: 'block', fontSize: '13px', color: 'var(--webcare-text-primary, #0f172a)' }}>No Targeted Allowlist Rules Active</strong>
          <p style={{ margin: '4px 0 12px 0', fontSize: '12px', color: 'var(--webcare-text-secondary, #64748b)' }}>
            Need third-party integrations (such as Klaviyo, Zapier, or payment webhooks) to access specific API endpoints without false-positive blocks? Create a targeted rule above.
          </p>
          <button
            type="button"
            className="webcare-btn"
            onClick={openAddModal}
            style={{
              background: '#4f46e5',
              color: '#ffffff',
              border: 'none',
              padding: '6px 14px',
              borderRadius: '6px',
              fontWeight: 600,
              fontSize: '12px',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '5px'
            }}
          >
            <Plus size={14} /> Create First Rule
          </button>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          {rules.map(rule => {
            const hasIps = rule.ip_addresses && rule.ip_addresses.length > 0;
            const trustTier = getRuleTrustTier(rule);
            return (
              <div
                key={rule.id}
                style={{
                  border: '1px solid var(--webcare-border-subtle, #e2e8f0)',
                  borderRadius: '8px',
                  padding: '14px 16px',
                  background: rule.enabled ? 'var(--webcare-bg-panel, #ffffff)' : 'var(--webcare-bg-surface, #f8fafc)',
                  opacity: rule.enabled ? 1 : 0.65,
                  transition: 'all 0.2s ease'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '10px', marginBottom: '8px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <input
                      type="checkbox"
                      checked={rule.enabled}
                      onChange={() => handleToggleRule(rule.id)}
                      title={rule.enabled ? 'Rule is Active (Click to disable)' : 'Rule is Disabled (Click to activate)'}
                      style={{ cursor: 'pointer', width: '16px', height: '16px' }}
                    />
                    <strong style={{ fontSize: '13px', color: 'var(--webcare-text-primary, #0f172a)' }}>
                      {rule.name}
                    </strong>
                    <span className={`webcare-badge-pill ${rule.enabled ? 'webcare-badge-clean' : 'webcare-badge-neutral'}`} style={{ fontSize: '10px', padding: '1px 6px' }}>
                      {rule.enabled ? 'Active' : 'Disabled'}
                    </span>
                    <span
                      className={`webcare-badge-pill ${
                        trustTier.level === 'high'
                          ? 'webcare-badge-clean'
                          : trustTier.level === 'medium'
                          ? 'webcare-badge-warning'
                          : 'webcare-badge-danger'
                      }`}
                      style={{ fontSize: '10px', padding: '1px 6px', display: 'inline-flex', alignItems: 'center', gap: '3px' }}
                      title={trustTier.desc}
                    >
                      <Shield size={10} />
                      {trustTier.label}
                    </span>
                    {rule.methods && (
                      <span className="webcare-badge-pill webcare-badge-info" style={{ fontSize: '10px', padding: '1px 6px' }}>
                        {rule.methods.join(', ')}
                      </span>
                    )}
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', position: 'relative' }}>
                    <button
                      type="button"
                      className="webcare-btn-micro"
                      onClick={() => openEditModal(rule)}
                      title="Edit Rule"
                    >
                      <Edit2 size={12} /> Edit
                    </button>
                    <button
                      type="button"
                      className="webcare-btn-micro"
                      onClick={() => setConfirmDeleteRuleId(confirmDeleteRuleId === rule.id ? null : rule.id)}
                      title="Delete Rule"
                      style={{ color: '#dc2626', borderColor: confirmDeleteRuleId === rule.id ? '#dc2626' : undefined }}
                    >
                      <Trash2 size={12} />
                    </button>

                    {/* Inline Delete Confirmation Popover directly below Delete button */}
                    {confirmDeleteRuleId === rule.id && (
                      <div
                        style={{
                          position: 'absolute',
                          top: 'calc(100% + 6px)',
                          right: 0,
                          zIndex: 100,
                          background: 'var(--webcare-bg-panel, #ffffff)',
                          border: '1px solid #fca5a5',
                          borderRadius: '8px',
                          padding: '10px 12px',
                          boxShadow: '0 8px 20px rgba(0, 0, 0, 0.15)',
                          minWidth: '220px',
                          display: 'flex',
                          flexDirection: 'column',
                          gap: '8px',
                          animation: 'fadeIn 0.15s ease'
                        }}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#dc2626', fontSize: '11px', fontWeight: 700 }}>
                          <AlertCircle size={14} />
                          <span>Delete this rule?</span>
                        </div>
                        <p style={{ margin: 0, fontSize: '11px', color: 'var(--webcare-text-secondary, #475569)', lineHeight: 1.35 }}>
                          This will permanently remove <strong>"{rule.name}"</strong>.
                        </p>
                        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '6px', marginTop: '2px' }}>
                          <button
                            type="button"
                            className="webcare-btn-micro"
                            onClick={() => setConfirmDeleteRuleId(null)}
                            style={{ fontSize: '11px', padding: '3px 8px' }}
                          >
                            Cancel
                          </button>
                          <button
                            type="button"
                            className="webcare-btn-micro"
                            onClick={() => handleDeleteRule(rule.id)}
                            style={{
                              background: '#dc2626',
                              color: '#ffffff',
                              border: '1px solid #b91c1c',
                              fontSize: '11px',
                              padding: '3px 10px',
                              fontWeight: 700,
                              borderRadius: '4px'
                            }}
                          >
                            Confirm Delete
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                {rule.description && (
                  <p style={{ margin: '0 0 10px 0', fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>
                    {rule.description}
                  </p>
                )}

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '10px', fontSize: '11px' }}>
                  {/* User-Agents */}
                  <div style={{ background: 'var(--webcare-bg-surface, #f8fafc)', padding: '8px 10px', borderRadius: '6px', border: '1px solid var(--webcare-border-subtle, #e2e8f0)' }}>
                    <span style={{ fontWeight: 700, color: 'var(--webcare-text-muted, #64748b)', display: 'block', marginBottom: '4px', textTransform: 'uppercase' }}>
                      User-Agents ({rule.user_agents?.length || 0})
                    </span>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                      {rule.user_agents && rule.user_agents.length > 0 ? (
                        rule.user_agents.map((ua, i) => (
                          <code key={i} style={{ background: 'rgba(79, 70, 229, 0.08)', color: '#4f46e5', padding: '2px 6px', borderRadius: '4px', fontSize: '10px' }}>
                            {ua}
                          </code>
                        ))
                      ) : (
                        <span style={{ color: 'var(--webcare-text-muted, #94a3b8)' }}>Any User-Agent (*)</span>
                      )}
                    </div>
                  </div>

                  {/* Endpoints */}
                  <div style={{ background: 'var(--webcare-bg-surface, #f8fafc)', padding: '8px 10px', borderRadius: '6px', border: '1px solid var(--webcare-border-subtle, #e2e8f0)' }}>
                    <span style={{ fontWeight: 700, color: 'var(--webcare-text-muted, #64748b)', display: 'block', marginBottom: '4px', textTransform: 'uppercase' }}>
                      Allowed Endpoints ({rule.endpoints?.length || 0})
                    </span>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                      {rule.endpoints && rule.endpoints.length > 0 ? (
                        rule.endpoints.map((ep, i) => (
                          <code key={i} style={{ background: 'rgba(2, 132, 199, 0.08)', color: '#0284c7', padding: '2px 6px', borderRadius: '4px', fontSize: '10px' }}>
                            {ep}
                          </code>
                        ))
                      ) : (
                        <span style={{ color: 'var(--webcare-text-muted, #94a3b8)' }}>Any Endpoint (*)</span>
                      )}
                    </div>
                  </div>

                  {/* IP Condition */}
                  <div style={{ background: 'var(--webcare-bg-surface, #f8fafc)', padding: '8px 10px', borderRadius: '6px', border: '1px solid var(--webcare-border-subtle, #e2e8f0)' }}>
                    <span style={{ fontWeight: 700, color: 'var(--webcare-text-muted, #64748b)', display: 'block', marginBottom: '4px', textTransform: 'uppercase' }}>
                      IP / Subnet Restriction
                    </span>
                    {hasIps ? (
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                        {rule.ip_addresses.map((ip, i) => (
                          <code key={i} style={{ background: 'rgba(16, 185, 129, 0.1)', color: '#059669', padding: '2px 6px', borderRadius: '4px', fontSize: '10px' }}>
                            {ip}
                          </code>
                        ))}
                      </div>
                    ) : (
                      <span className="webcare-badge-pill webcare-badge-neutral" style={{ fontSize: '10px' }}>
                        Any IP (Unrestricted)
                      </span>
                    )}
                  </div>

                  {/* Hostnames / rDNS Condition */}
                  {rule.hostnames && rule.hostnames.length > 0 && (
                    <div style={{ background: 'var(--webcare-bg-surface, #f8fafc)', padding: '8px 10px', borderRadius: '6px', border: '1px solid var(--webcare-border-subtle, #e2e8f0)' }}>
                      <span style={{ fontWeight: 700, color: 'var(--webcare-text-muted, #64748b)', display: 'block', marginBottom: '4px', textTransform: 'uppercase' }}>
                        Reverse DNS / Hostnames ({rule.hostnames.length})
                      </span>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                        {rule.hostnames.map((hn, i) => (
                          <code key={i} style={{ background: 'rgba(124, 58, 237, 0.08)', color: '#7c3aed', padding: '2px 6px', borderRadius: '4px', fontSize: '10px' }}>
                            {hn}
                          </code>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* ASN Condition */}
                  {rule.asns && rule.asns.length > 0 && (
                    <div style={{ background: 'var(--webcare-bg-surface, #f8fafc)', padding: '8px 10px', borderRadius: '6px', border: '1px solid var(--webcare-border-subtle, #e2e8f0)' }}>
                      <span style={{ fontWeight: 700, color: 'var(--webcare-text-muted, #64748b)', display: 'block', marginBottom: '4px', textTransform: 'uppercase' }}>
                        Authorized ASN ({rule.asns.length})
                      </span>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                        {rule.asns.map((asn, i) => (
                          <code key={i} style={{ background: 'rgba(234, 88, 12, 0.08)', color: '#c2410c', padding: '2px 6px', borderRadius: '4px', fontSize: '10px' }}>
                            {asn}
                          </code>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Required Security Headers */}
                  {rule.required_headers && rule.required_headers.length > 0 && (
                    <div style={{ background: 'var(--webcare-bg-surface, #f8fafc)', padding: '8px 10px', borderRadius: '6px', border: '1px solid var(--webcare-border-subtle, #e2e8f0)' }}>
                      <span style={{ fontWeight: 700, color: 'var(--webcare-text-muted, #64748b)', display: 'block', marginBottom: '4px', textTransform: 'uppercase' }}>
                        Security Headers ({rule.required_headers.length})
                      </span>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                        {rule.required_headers.map((hdr, i) => (
                          <code key={i} style={{ background: 'rgba(16, 185, 129, 0.08)', color: '#047857', padding: '2px 6px', borderRadius: '4px', fontSize: '10px' }}>
                            {hdr}
                          </code>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Modal Dialog for Add / Edit Rule */}
      {modalOpen && (
        <div
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: 'rgba(0, 0, 0, 0.65)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 100000,
            padding: '20px'
          }}
          onClick={() => setModalOpen(false)}
        >
          <div
            style={{
              background: 'var(--webcare-bg-panel, #ffffff)',
              borderRadius: '10px',
              maxWidth: '620px',
              width: '100%',
              padding: '24px',
              boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.3)',
              maxHeight: '90vh',
              overflowY: 'auto',
              border: '1px solid var(--webcare-border-subtle, #cbd5e1)'
            }}
            onClick={e => e.stopPropagation()}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
              <h3 style={{ margin: 0, fontSize: '16px', display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--webcare-text-primary, #0f172a)' }}>
                <Radio size={18} color="#4f46e5" />
                {editingRuleId ? 'Edit Targeted Allowlist Rule' : 'New Targeted Allowlist Rule'}
              </h3>
              <button
                type="button"
                onClick={() => setModalOpen(false)}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--webcare-text-muted, #94a3b8)' }}
              >
                <X size={18} />
              </button>
            </div>

            {formError && (
              <div style={{ padding: '8px 12px', background: '#fef2f2', border: '1px solid #fecaca', color: '#991b1b', borderRadius: '6px', fontSize: '12px', marginBottom: '14px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <AlertCircle size={14} />
                <span>{formError}</span>
              </div>
            )}

            {/* Dynamic Security Trust Tier Indicator */}
            {(() => {
              const currentTier = getRuleTrustTier({
                ip_addresses: formIps.split('\n').filter(Boolean),
                hostnames: formHostnames.split('\n').filter(Boolean),
                asns: formAsns.split('\n').filter(Boolean),
                required_headers: formHeaders.split('\n').filter(Boolean)
              });

              return (
                <div
                  style={{
                    padding: '10px 12px',
                    borderRadius: '6px',
                    marginBottom: '14px',
                    fontSize: '11.5px',
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: '8px',
                    background:
                      currentTier.level === 'high'
                        ? 'rgba(16, 185, 129, 0.08)'
                        : currentTier.level === 'medium'
                        ? 'rgba(245, 158, 11, 0.08)'
                        : 'rgba(239, 68, 68, 0.08)',
                    border:
                      currentTier.level === 'high'
                        ? '1px solid rgba(16, 185, 129, 0.3)'
                        : currentTier.level === 'medium'
                        ? '1px solid rgba(245, 158, 11, 0.3)'
                        : '1px solid rgba(239, 68, 68, 0.3)'
                  }}
                >
                  <Shield
                    size={16}
                    color={
                      currentTier.level === 'high'
                        ? '#10b981'
                        : currentTier.level === 'medium'
                        ? '#d97706'
                        : '#dc2626'
                    }
                    style={{ flexShrink: 0, marginTop: '1px' }}
                  />
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <strong
                        style={{
                          color:
                            currentTier.level === 'high'
                              ? '#047857'
                              : currentTier.level === 'medium'
                              ? '#b45309'
                              : '#b91c1c'
                        }}
                      >
                        Security Posture: {currentTier.label}
                      </strong>
                    </div>
                    <span style={{ color: 'var(--webcare-text-secondary, #475569)', fontSize: '11px', lineHeight: 1.4, display: 'block', marginTop: '2px' }}>
                      {currentTier.desc}
                    </span>
                  </div>
                </div>
              );
            })()}

            {/* Rule Name */}
            <div style={{ marginBottom: '14px' }}>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: 700, marginBottom: '4px', color: 'var(--webcare-text-primary, #0f172a)' }}>
                Rule Name <span style={{ color: '#dc2626' }}>*</span>
              </label>
              <input
                type="text"
                value={formName}
                onChange={e => setFormName(e.target.value)}
                placeholder="e.g. Klaviyo WooCommerce Orders Sync"
                className="webcare-input"
                style={{ width: '100%', fontSize: '13px' }}
              />
            </div>

            {/* User Agents */}
            <div style={{ marginBottom: '14px' }}>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: 700, marginBottom: '4px', color: 'var(--webcare-text-primary, #0f172a)' }}>
                Client User-Agents (One per line, supports wildcard <code>*</code>)
              </label>
              <textarea
                rows={3}
                value={formUas}
                onChange={e => setFormUas(e.target.value)}
                placeholder="e.g.&#10;EFS-IS2-WooCommerce/v1&#10;*Klaviyo*&#10;WooCommerce/*"
                className="webcare-input"
                style={{ width: '100%', fontFamily: 'monospace', fontSize: '12px' }}
              />
              <span style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>
                Leave blank to allow any User-Agent matching the endpoint.
              </span>
            </div>

            {/* Endpoints */}
            <div style={{ marginBottom: '14px' }}>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: 700, marginBottom: '4px', color: 'var(--webcare-text-primary, #0f172a)' }}>
                Target Endpoints / URL Paths (One per line, supports wildcard <code>*</code>)
              </label>
              <textarea
                rows={3}
                value={formEndpoints}
                onChange={e => setFormEndpoints(e.target.value)}
                placeholder="e.g.&#10;/wp-json/wc/v2/orders/*&#10;/wp-json/wc/v3/orders/*&#10;/wp-json/my-api/*"
                className="webcare-input"
                style={{ width: '100%', fontFamily: 'monospace', fontSize: '12px' }}
              />
              <span style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>
                Leave blank to allow any URL path matching the User-Agent.
              </span>
            </div>

            {/* IP / Subnet */}
            <div style={{ marginBottom: '14px' }}>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: 700, marginBottom: '4px', color: 'var(--webcare-text-primary, #0f172a)' }}>
                Authorized Client IPs or CIDR Subnets (Optional, one per line)
              </label>
              <textarea
                rows={2}
                value={formIps}
                onChange={e => setFormIps(e.target.value)}
                placeholder="e.g.&#10;192.168.1.50&#10;198.51.100.0/24"
                className="webcare-input"
                style={{ width: '100%', fontFamily: 'monospace', fontSize: '12px' }}
              />
              <span style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>
                <strong>Leave blank to allow Any IP</strong>. If IPs are specified, incoming requests must match the IP range.
              </span>
            </div>

            {/* Hostnames / Reverse DNS (rDNS) */}
            <div style={{ marginBottom: '14px' }}>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: 700, marginBottom: '4px', color: 'var(--webcare-text-primary, #0f172a)' }}>
                Authorized Hostnames / Reverse DNS (rDNS) (Optional, one per line)
              </label>
              <textarea
                rows={2}
                value={formHostnames}
                onChange={e => setFormHostnames(e.target.value)}
                placeholder="e.g.&#10;paypal.com&#10;stripe.com&#10;*.googlebot.com"
                className="webcare-input"
                style={{ width: '100%', fontFamily: 'monospace', fontSize: '12px' }}
              />
              <span style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>
                WAF performs verified 2-way reverse + forward DNS lookup to prevent hostname spoofing.
              </span>
            </div>

            {/* ASN Numbers */}
            <div style={{ marginBottom: '14px' }}>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: 700, marginBottom: '4px', color: 'var(--webcare-text-primary, #0f172a)' }}>
                Autonomous System Numbers (ASN) (Optional, one per line)
              </label>
              <textarea
                rows={2}
                value={formAsns}
                onChange={e => setFormAsns(e.target.value)}
                placeholder="e.g.&#10;AS2635&#10;AS62679&#10;AS32934"
                className="webcare-input"
                style={{ width: '100%', fontFamily: 'monospace', fontSize: '12px' }}
              />
              <span style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>
                Matches Autonomous System Number (e.g. AS2635 Automattic, AS62679 Shopify, AS32934 Meta).
              </span>
            </div>

            {/* Required Security Headers */}
            <div style={{ marginBottom: '14px' }}>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: 700, marginBottom: '4px', color: 'var(--webcare-text-primary, #0f172a)' }}>
                Required Security / Webhook Signature Headers (Optional, one per line)
              </label>
              <textarea
                rows={2}
                value={formHeaders}
                onChange={e => setFormHeaders(e.target.value)}
                placeholder="e.g.&#10;X-Shopify-Hmac-Sha256&#10;Stripe-Signature&#10;X-Square-Hmacsha256-Signature"
                className="webcare-input"
                style={{ width: '100%', fontFamily: 'monospace', fontSize: '12px' }}
              />
              <span style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>
                Requires incoming request to present this HTTP header (e.g. webhook HMAC signature) to prevent forged calls.
              </span>
            </div>

            {/* HTTP Methods */}
            <div style={{ marginBottom: '14px' }}>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: 700, marginBottom: '6px', color: 'var(--webcare-text-primary, #0f172a)' }}>
                HTTP Methods Allowed
              </label>
              <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                {['ALL', 'GET', 'POST', 'PUT', 'DELETE', 'PATCH'].map(method => {
                  const isSelected = formMethods.includes(method);
                  return (
                    <button
                      key={method}
                      type="button"
                      className={`webcare-btn-micro ${isSelected ? 'is-active-method' : ''}`}
                      onClick={() => toggleMethod(method)}
                      style={{
                        padding: '6px 14px',
                        fontWeight: 700,
                        fontSize: '11.5px',
                        borderRadius: '6px',
                        cursor: 'pointer',
                        transition: 'all 0.15s ease',
                        border: isSelected ? '1px solid #059669' : '1px solid #cbd5e1',
                        background: isSelected ? '#10b981' : '#ffffff',
                        color: isSelected ? '#ffffff' : '#334155',
                        boxShadow: isSelected ? '0 2px 5px rgba(16, 185, 129, 0.35)' : 'none'
                      }}
                    >
                      {isSelected && <Check size={12} strokeWidth={3} style={{ marginRight: '3px' }} />}
                      {method}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Description */}
            <div style={{ marginBottom: '16px' }}>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: 700, marginBottom: '4px', color: 'var(--webcare-text-primary, #0f172a)' }}>
                Notes / Integration Context (Optional)
              </label>
              <input
                type="text"
                value={formDesc}
                onChange={e => setFormDesc(e.target.value)}
                placeholder="e.g. Sync worker for Klaviyo newsletter & checkout abandoned cart tracking."
                className="webcare-input"
                style={{ width: '100%', fontSize: '12px' }}
              />
            </div>

            {/* Scope Preview Summary */}
            <div
              style={{
                marginBottom: '16px',
                padding: '10px 14px',
                borderRadius: '8px',
                background: 'var(--webcare-bg-subtle, rgba(79, 70, 229, 0.04))',
                border: '1px solid var(--webcare-border, #e2e8f0)',
                fontSize: '11px',
                lineHeight: '1.5',
                color: 'var(--webcare-text-secondary, #475569)'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontWeight: 700, marginBottom: '6px', color: 'var(--webcare-text-primary, #0f172a)' }}>
                <Shield size={13} style={{ color: '#4f46e5' }} />
                <span>Targeted Allowlist Scope Preview</span>
              </div>
              <div style={{ marginBottom: '3px' }}>
                <strong style={{ color: 'var(--webcare-text-primary, #0f172a)' }}>Matching Endpoints: </strong>
                <span>
                  {formEndpoints.split('\n').map(s => s.trim()).filter(Boolean).length > 0
                    ? formEndpoints.split('\n').map(s => s.trim()).filter(Boolean).join(', ')
                    : 'Any (governed by IP/UA/ASN/Hostname constraints)'}
                </span>
              </div>
              <div style={{ marginBottom: '3px' }}>
                <strong style={{ color: 'var(--webcare-text-primary, #0f172a)' }}>HTTP Methods: </strong>
                <span>{formMethods.length > 0 ? formMethods.join(', ') : 'ALL'}</span>
              </div>
              <div style={{ marginBottom: '4px' }}>
                <strong style={{ color: 'var(--webcare-text-primary, #0f172a)' }}>Suppressed Checks: </strong>
                <span>Operational rate limits, protocol anomaly checks &amp; heuristic payload inspectors for matching endpoints.</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '4px', color: '#047857', fontWeight: 600, marginTop: '4px', fontSize: '10.5px' }}>
                <Check size={12} />
                <span>Zero-tolerance exploit checks (SQLi, RCE, LFI, XXE, SSRF) remain 100% active.</span>
              </div>
            </div>

            {/* Modal Actions */}
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
              <button
                type="button"
                className="webcare-btn"
                onClick={() => setModalOpen(false)}
                style={{ padding: '6px 14px', fontSize: '12px' }}
              >
                Cancel
              </button>
              <button
                type="button"
                className="webcare-btn"
                onClick={handleSaveModal}
                style={{
                  background: '#4f46e5',
                  color: '#ffffff',
                  border: 'none',
                  padding: '6px 16px',
                  borderRadius: '6px',
                  fontWeight: 600,
                  fontSize: '12px'
                }}
              >
                {editingRuleId ? 'Update Rule' : 'Save & Activate Rule'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

