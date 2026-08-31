import type {ReactNode} from 'react';
import Link from '@docusaurus/Link';
import useBaseUrl from '@docusaurus/useBaseUrl';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import Layout from '@theme/Layout';
import Heading from '@theme/Heading';

import styles from './index.module.css';

const features = [
  {
    title: 'Blocklists',
    body: 'Load IP, hostname, and User-Agent deny lists from files. RavenGuard reloads them on a timer without restarting.',
  },
  {
    title: 'Rate limits and size caps',
    body: 'Limit requests per client, concurrent work, and body/header/URL size. Repeat offenders get a temporary ban.',
  },
  {
    title: 'Scanner scoring',
    body: 'Scores requests for scanner User-Agents, missing browser headers, probe paths, and short-window path fan-out. High scores challenge or block.',
  },
  {
    title: 'Browser challenge',
    body: 'Optional JavaScript proof-of-work plus an environment probe. Clearance is an HMAC cookie bound to the client key.',
  },
  {
    title: 'Hashed client IPs',
    body: 'Rate limits, behavior state, and logs use a hashed client key by default. Raw addresses stay out of memory unless you turn that off.',
  },
  {
    title: 'Q-Feeds',
    body: 'Optional malware IP and domain feeds from Q-Feeds refresh into the same deny path as local blocklists.',
  },
];

const pipeline = [
  {
    title: 'Client IP',
    body: 'Take the address from trusted proxies via X-Real-IP, X-Forwarded-For, or PROXY protocol.',
  },
  {
    title: 'Deny and throttle',
    body: 'Apply blocklists, optional feeds, rate limits, size caps, and attack signatures.',
  },
  {
    title: 'Detect',
    body: 'Score the request. Challenge or hard-block before the origin sees it.',
  },
  {
    title: 'Proxy',
    body: 'Forward allowed traffic to HTTP or unix upstreams. Rebuild X-Real-IP and X-Forwarded-For from the resolved client.',
  },
];

function HomepageHeader(): ReactNode {
  const {siteConfig} = useDocusaurusContext();
  const raven = useBaseUrl('/img/raven.png');

  return (
    <header className={styles.hero}>
      <div className={styles.heroInner}>
        <div>
          <p className={styles.orgLine}>
            <a
              className={styles.orgLink}
              href="https://github.com/Quad4-Software"
              target="_blank"
              rel="noopener noreferrer">
              A Quad4 Software Project
            </a>
          </p>
          <Heading as="h1" className={styles.brandName}>
            {siteConfig.title}
          </Heading>
          <p className={styles.headline}>
            Sits behind your reverse proxy and in front of the origin.
          </p>
          <p className={styles.lede}>
            Terminates nothing. Checks the request, then forwards HTTP or unix
            upstream. Blocklists, rate limits, attack filters, detect scoring,
            and an optional browser challenge.
          </p>
          <div className={styles.actions}>
            <Link className="button button--primary button--lg" to="/docs/intro">
              Docs
            </Link>
            <Link
              className="button button--outline button--lg"
              to="/docs/architecture">
              Architecture
            </Link>
          </div>
        </div>
        <div className={styles.visual} aria-hidden="true">
          <img className={styles.raven} src={raven} width={180} height={180} alt="" />
        </div>
      </div>
      <div className={styles.topology}>
        <div className={styles.topologyInner}>
          <strong>Client</strong>
          <span className={styles.sep}>{'->'}</span>
          <span>Reverse proxy</span>
          <span className={styles.sep}>{'->'}</span>
          <strong>RavenGuard</strong>
          <span className={styles.sep}>{'->'}</span>
          <span>Origin</span>
        </div>
      </div>
    </header>
  );
}

export default function Home(): ReactNode {
  return (
    <Layout
      title="Docs"
      description="RavenGuard: application guard between reverse proxy and HTTP origin. Blocklists, rate limits, detect scoring, browser challenge.">
      <HomepageHeader />
      <main>
        <section className={styles.section}>
          <div className={styles.containerNarrow}>
            <div className={styles.sectionHead}>
              <Heading as="h2" className={styles.sectionTitle}>
                What it does
              </Heading>
              <p className={styles.sectionCopy}>
                TLS stays on nginx, Caddy, or Traefik. RavenGuard runs on the
                private hop and decides what reaches the app.
              </p>
            </div>
            <div className={styles.featureGrid}>
              {features.map((feature) => (
                <article key={feature.title} className={styles.feature}>
                  <Heading as="h3" className={styles.featureTitle}>
                    {feature.title}
                  </Heading>
                  <p className={styles.featureCopy}>{feature.body}</p>
                </article>
              ))}
            </div>
          </div>
        </section>

        <section className={`${styles.section} ${styles.sectionAlt}`}>
          <div className={styles.containerNarrow}>
            <div className={styles.sectionHead}>
              <Heading as="h2" className={styles.sectionTitle}>
                Request order
              </Heading>
              <p className={styles.sectionCopy}>
                Every request hits the same stages in order.
              </p>
            </div>
            <div className={styles.pipeline}>
              {pipeline.map((step, index) => (
                <article key={step.title} className={styles.step}>
                  <span className={styles.stepIndex}>
                    {String(index + 1).padStart(2, '0')}
                  </span>
                  <Heading as="h3" className={styles.stepTitle}>
                    {step.title}
                  </Heading>
                  <p className={styles.stepCopy}>{step.body}</p>
                </article>
              ))}
            </div>
          </div>
        </section>

        <section className={styles.ctaBand}>
          <div className={styles.ctaInner}>
            <div>
              <Heading as="h2" className={styles.ctaTitle}>
                Build and run
              </Heading>
              <p className={styles.ctaCopy}>
                Run make build, or docker compose up --build from the deploy
                directory. Point upstream.url at the app and set
                RG_CHALLENGE_SECRET before you expose the challenge path.
              </p>
            </div>
            <div className={styles.actions}>
              <Link className="button button--primary button--lg" to="/docs/deployment">
                Deployment
              </Link>
              <Link
                className="button button--outline button--lg"
                href="https://github.com/Quad4-Software/ravenguard">
                Source
              </Link>
            </div>
          </div>
        </section>
      </main>
    </Layout>
  );
}
