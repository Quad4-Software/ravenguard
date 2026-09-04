import type {ReactNode} from 'react';
import Link from '@docusaurus/Link';
import useBaseUrl from '@docusaurus/useBaseUrl';
import {useThemeConfig} from '@docusaurus/theme-common';

import styles from './styles.module.css';

type FooterLink = {
  label: string;
  to?: string;
  href?: string;
};

const links: FooterLink[] = [
  {label: 'Intro', to: '/docs/intro'},
  {label: 'Architecture', to: '/docs/architecture'},
  {label: 'Config', to: '/docs/configuration'},
  {label: 'Deployment', to: '/docs/deployment'},
  {label: 'Admin', to: '/docs/admin'},
  {label: 'GitHub', href: 'https://github.com/Quad4-Software/ravenguard'},
  {
    label: 'License',
    href: 'https://github.com/Quad4-Software/ravenguard/blob/main/LICENSE',
  },
];

function Footer(): ReactNode {
  const {footer} = useThemeConfig();
  if (!footer) {
    return null;
  }

  const raven = useBaseUrl('/img/raven.png');
  const copyright =
    footer.copyright ??
    `Copyright © ${new Date().getFullYear()} Quad4. RavenGuard is licensed under 0BSD.`;

  return (
    <footer className={styles.footer}>
      <div className={styles.inner}>
        <div className={styles.top}>
          <Link className={styles.brand} to="/">
            <img
              className={styles.mark}
              src={raven}
              alt=""
              width={22}
              height={22}
            />
            <span className={styles.name}>RavenGuard</span>
          </Link>

          <nav className={styles.links} aria-label="Footer">
            {links.map((item) =>
              item.href ? (
                <a
                  key={item.label}
                  className={styles.link}
                  href={item.href}
                  target="_blank"
                  rel="noopener noreferrer">
                  {item.label}
                </a>
              ) : (
                <Link key={item.label} className={styles.link} to={item.to!}>
                  {item.label}
                </Link>
              ),
            )}
          </nav>
        </div>

        <div className={styles.meta}>
          <a
            className={styles.org}
            href="https://github.com/Quad4-Software"
            target="_blank"
            rel="noopener noreferrer">
            A Quad4 Software Project
          </a>
          <div
            className={styles.copyright}
            dangerouslySetInnerHTML={{__html: copyright}}
          />
        </div>
      </div>
    </footer>
  );
}

export default Footer;
