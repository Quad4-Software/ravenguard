import type {ReactNode} from 'react';
import {useCallback} from 'react';
import clsx from 'clsx';
import Link from '@docusaurus/Link';
import useBaseUrl from '@docusaurus/useBaseUrl';
import {
  ThemeClassNames,
  useColorMode,
  useThemeConfig,
} from '@docusaurus/theme-common';
import {useNavbarMobileSidebar} from '@docusaurus/theme-common/internal';
import {useLocation} from '@docusaurus/router';
import NavbarMobileSidebar from '@theme/Navbar/MobileSidebar';

import styles from './styles.module.css';

type NavLink = {
  label: string;
  to?: string;
  href?: string;
};

const links: NavLink[] = [
  {label: 'Docs', to: '/docs/intro'},
  {label: 'Config', to: '/docs/configuration'},
  {
    label: 'GitHub',
    href: 'https://github.com/Quad4-Software/ravenguard',
  },
];

function isActive(pathname: string, to?: string): boolean {
  if (!to) {
    return false;
  }
  if (to === '/docs/intro') {
    return (
      pathname.startsWith('/docs') &&
      !pathname.startsWith('/docs/configuration')
    );
  }
  return pathname === to || pathname.startsWith(`${to}/`);
}

function ColorModeButton(): ReactNode {
  const {disableSwitch} = useThemeConfig().colorMode;
  const {colorMode, setColorMode} = useColorMode();

  const toggle = useCallback(() => {
    setColorMode(colorMode === 'dark' ? 'light' : 'dark');
  }, [colorMode, setColorMode]);

  if (disableSwitch) {
    return null;
  }

  const next = colorMode === 'dark' ? 'light' : 'dark';

  return (
    <button
      type="button"
      className={styles.modeToggle}
      onClick={toggle}
      aria-label={`Switch to ${next} mode`}>
      {colorMode === 'dark' ? (
        <svg
          className={styles.modeIcon}
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          aria-hidden="true">
          <circle cx="12" cy="12" r="5" />
          <path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42" />
        </svg>
      ) : (
        <svg
          className={styles.modeIcon}
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          aria-hidden="true">
          <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
        </svg>
      )}
    </button>
  );
}

function NavLinks({className}: {className?: string}): ReactNode {
  const {pathname} = useLocation();
  const baseUrl = useBaseUrl('/');
  const normalized =
    baseUrl !== '/' && pathname.startsWith(baseUrl)
      ? pathname.slice(baseUrl.length - 1) || '/'
      : pathname;

  return (
    <div className={className}>
      {links.map((item) => {
        const active = isActive(normalized, item.to);
        if (item.href) {
          return (
            <a
              key={item.label}
              className={styles.link}
              href={item.href}
              target="_blank"
              rel="noopener noreferrer">
              {item.label}
            </a>
          );
        }
        return (
          <Link
            key={item.label}
            className={clsx(styles.link, active && styles.linkActive)}
            to={item.to!}>
            {item.label}
          </Link>
        );
      })}
    </div>
  );
}

export default function Navbar(): ReactNode {
  const raven = useBaseUrl('/img/raven.png');
  const mobileSidebar = useNavbarMobileSidebar();

  return (
    <nav
      aria-label="Main"
      className={clsx(
        ThemeClassNames.layout.navbar.container,
        'navbar',
        'navbar--fixed-top',
        styles.bar,
        mobileSidebar.shown && 'navbar-sidebar--show',
      )}>
      <div className={styles.inner}>
        {!mobileSidebar.disabled && (
          <button
            type="button"
            className={styles.menuToggle}
            onClick={mobileSidebar.toggle}
            aria-label="Toggle navigation"
            aria-expanded={mobileSidebar.shown}>
            <span className={styles.menuIcon} aria-hidden="true">
              <span />
              <span />
              <span />
            </span>
          </button>
        )}

        <Link className={styles.brand} to="/">
          <img className={styles.mark} src={raven} alt="" width={26} height={26} />
          <span className={styles.name}>RavenGuard</span>
        </Link>

        <NavLinks className={styles.nav} />

        <div className={styles.actions}>
          <ColorModeButton />
        </div>
      </div>

      <div
        role="presentation"
        className="navbar-sidebar__backdrop"
        onClick={mobileSidebar.toggle}
      />
      <NavbarMobileSidebar />
    </nav>
  );
}
