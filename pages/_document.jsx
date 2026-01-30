import { Html, Head, Main, NextScript } from 'next/document'

export default function Document() {
  return (
    <Html>
      <Head>
        <link rel="icon" href="/favicon.svg" type="image/svg+xml" />
        <link rel="apple-touch-icon" href="/favicon.svg" />
        <meta name="theme-color" content="#0f172a" />
        <meta name="description" content="Cyber Security Cheatsheet - Penetration Testing Tools Reference" />
      </Head>
      <body>
        <Main />
        <NextScript />
      </body>
    </Html>
  )
}
