import {themes as prismThemes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

const config: Config = {
  title: 'RavenGuard',
  tagline: 'HTTP guard between reverse proxy and origin.',
  favicon: 'img/favicon.ico',

  future: {
    v4: true,
  },

  url: 'https://quad4-software.github.io',
  baseUrl: '/ravenguard/',
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
      } satisfies Preset.Options,
    ],
  ],

  themeConfig: {
    image: 'img/raven.png',
    metadata: [
      {
        name: 'description',
        content:
          'HTTP application guard between reverse proxy and origin. Blocklists, rate limits, detect scoring, optional browser challenge.',
      },
      {name: 'theme-color', content: '#050505'},
    ],
    colorMode: {
      defaultMode: 'dark',
      disableSwitch: false,
      respectPrefersColorScheme: true,
    },
    announcementBar: {
      id: 'alpha',
      content:
        'Alpha. Actively developed. Not ready for production.',
      backgroundColor: '#1a1a1a',
      textColor: '#c4c4c4',
      isCloseable: false,
    },
    navbar: {
      title: 'RavenGuard',
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
      links: [
        {
          title: 'Docs',
          items: [
            {label: 'Getting started', to: '/docs/intro'},
            {label: 'Architecture', to: '/docs/architecture'},
            {label: 'Configuration', to: '/docs/configuration'},
            {label: 'Deployment', to: '/docs/deployment'},
          ],
        },
        {
          title: 'Guides',
          items: [
            {label: 'Challenge and UI', to: '/docs/challenge-ui'},
            {label: 'Detection', to: '/docs/detection'},
            {label: 'Privacy', to: '/docs/privacy'},
            {label: 'Testing', to: '/docs/testing'},
          ],
        },
        {
          title: 'Project',
          items: [
            {
              label: 'A Quad4 Software Project',
              href: 'https://github.com/Quad4-Software',
            },
            {
              label: 'GitHub',
              href: 'https://github.com/Quad4-Software/ravenguard',
            },
            {
              label: 'License (0BSD)',
              href: 'https://github.com/Quad4-Software/ravenguard/blob/main/LICENSE',
            },
          ],
        },
      ],
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
