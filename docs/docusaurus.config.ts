import {themes as prismThemes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

const config: Config = {
  title: 'RavenGuard',
  tagline:
    'HTTP WAF and reverse proxy. Edge or fleet with a private hub.',
  favicon: 'img/favicon.ico',

  future: {
    v4: true,
  },

  url: 'https://ravenguard.quad4.io',
  baseUrl: '/',
  trailingSlash: false,

  organizationName: 'Quad4-Software',
  projectName: 'ravenguard',

  onBrokenLinks: 'throw',

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      {
        docs: {
          sidebarPath: './sidebars.ts',
          editUrl:
            'https://github.com/Quad4-Software/ravenguard/tree/main/docs/',
          routeBasePath: 'docs',
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
        sitemap: {
          changefreq: 'weekly',
          priority: 0.5,
          filename: 'sitemap.xml',
        },
      } satisfies Preset.Options,
    ],
  ],

  themeConfig: {
    image: 'img/raven.png',
    metadata: [
      {
        name: 'description',
        content:
          'HTTP WAF and reverse proxy with blocklists, rate limits, detect scoring, browser challenge, admin control plane, and hub plus proxy fleet.',
      },
      {name: 'theme-color', content: '#050505'},
      {name: 'robots', content: 'index, follow, noai, noimageai'},
      {name: 'googlebot', content: 'index, follow'},
      {name: 'bingbot', content: 'index, follow'},
      {name: 'GPTBot', content: 'noindex, nofollow'},
      {name: 'ChatGPT-User', content: 'noindex, nofollow'},
      {name: 'ClaudeBot', content: 'noindex, nofollow'},
      {name: 'anthropic-ai', content: 'noindex, nofollow'},
      {name: 'Google-Extended', content: 'noindex, nofollow'},
      {name: 'Applebot-Extended', content: 'noindex, nofollow'},
      {name: 'CCBot', content: 'noindex, nofollow'},
      {name: 'Bytespider', content: 'noindex, nofollow'},
      {name: 'PerplexityBot', content: 'noindex, nofollow'},
    ],
    colorMode: {
      defaultMode: 'dark',
      disableSwitch: false,
      respectPrefersColorScheme: true,
    },
    navbar: {
      title: 'RavenGuard',
      hideOnScroll: false,
      logo: {
        alt: 'RavenGuard',
        src: 'img/raven.png',
        srcDark: 'img/raven.png',
        width: 28,
        height: 28,
      },
      items: [
        {
          type: 'docSidebar',
          sidebarId: 'docsSidebar',
          position: 'left',
          label: 'Docs',
        },
        {
          to: '/docs/configuration',
          label: 'Config',
          position: 'left',
        },
        {
          href: 'https://github.com/Quad4-Software/ravenguard',
          label: 'GitHub',
          position: 'right',
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [],
      copyright: `Copyright © ${new Date().getFullYear()} Quad4. RavenGuard is licensed under 0BSD.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.oneDark,
      additionalLanguages: ['bash', 'toml', 'nginx', 'docker'],
    },
  } satisfies Preset.ThemeConfig,

  headTags: [
    {
      tagName: 'meta',
      attributes: {
        name: 'ai',
        content: 'notrain, noindex',
      },
    },
    {
      tagName: 'link',
      attributes: {
        rel: 'llms',
        href: '/llms.txt',
      },
    },
    {
      tagName: 'link',
      attributes: {
        rel: 'preconnect',
        href: 'https://fonts.googleapis.com',
      },
    },
    {
      tagName: 'link',
      attributes: {
        rel: 'preconnect',
        href: 'https://fonts.gstatic.com',
        crossorigin: 'anonymous',
      },
    },
    {
      tagName: 'link',
      attributes: {
        rel: 'stylesheet',
        href: 'https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@400;500;600&display=swap',
      },
    },
  ],
};

export default config;
