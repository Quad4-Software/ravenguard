import type {SidebarsConfig} from '@docusaurus/plugin-content-docs';

const sidebars: SidebarsConfig = {
  docsSidebar: [
    'intro',
    'architecture',
    {
      type: 'category',
      label: 'Operate',
      collapsed: false,
      items: [
        'deployment',
        'configuration',
        'admin',
        'blocklists',
        'challenge-ui',
        'requests',
      ],
    },
    {
      type: 'category',
      label: 'Protect',
      collapsed: false,
      items: ['detection', 'coraza', 'openapi', 'privacy'],
    },
    'testing',
  ],
};

export default sidebars;
