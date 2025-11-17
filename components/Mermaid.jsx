import { useEffect, useState } from 'react'
import PropTypes from 'prop-types'

export default function Mermaid({ chart, theme = 'dark' }) {
  const [svg, setSvg] = useState('')

  useEffect(() => {
    let mounted = true
    ;(async () => {
      try {
        const { default: mermaid } = await import('mermaid')
        mermaid.initialize({ startOnLoad: false, theme })
        const id = `mermaid-${Math.random().toString(36).slice(2)}`
        const res = await mermaid.render(id, chart)
        if (mounted) setSvg(res.svg || '')
      } catch (e) {
        if (mounted) setSvg(`<pre class="text-red-400">${e?.message || 'Mermaid render error'}</pre>`) 
      }
    })()
    return () => { mounted = false }
  }, [chart, theme])

  return <div className="mermaid-diagram" dangerouslySetInnerHTML={{ __html: svg }} />
}

Mermaid.propTypes = {
  chart: PropTypes.string.isRequired,
  theme: PropTypes.oneOf(['default', 'dark'])
}