import { useEffect } from 'react'
import PropTypes from 'prop-types'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import remarkSlug from 'remark-slug'
import remarkToc from 'remark-toc'
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter'
import oneDark from 'react-syntax-highlighter/dist/cjs/styles/prism/one-dark'
import Mermaid from './Mermaid'

export default function MarkdownEditor({ value, onChange }) {
  useEffect(() => {
    // Add copy buttons to code blocks in preview
    const container = document.querySelector('#md-editor-preview')
    if (!container) return
    const blocks = container.querySelectorAll('pre')
    blocks.forEach((pre) => {
      if (pre.querySelector('.copy-btn')) return
      const btn = document.createElement('button')
      btn.textContent = 'Copy'
      btn.className = 'copy-btn btn-secondary absolute right-2 top-2 text-xs'
      btn.addEventListener('click', () => {
        const code = pre.querySelector('code')
        const text = code ? code.textContent : ''
        navigator.clipboard.writeText(text || '')
        btn.textContent = 'Copied!'
        setTimeout(() => (btn.textContent = 'Copy'), 1200)
      })
      pre.style.position = 'relative'
      pre.appendChild(btn)
    })
  }, [value])

  return (
    <div className="grid md:grid-cols-2 gap-4">
      <div className="panel p-2">
        <textarea
          value={value}
          onChange={(e) => onChange(e.target.value)}
          className="w-full h-[400px] px-3 py-2 rounded bg-gray-900 border border-gray-800"
          placeholder="Write markdown here..."
        />
      </div>
      <div id="md-editor-preview" className="panel p-4 prose prose-invert max-w-none">
        {typeof window !== 'undefined' && (
          <ReactMarkdown
            remarkPlugins={[remarkGfm, remarkSlug, remarkToc]}
            components={{
              code({ inline, className, children, ...props }) {
                const match = /language-(\w+)/.exec(className || '')
                if (!inline && match && match[1] === 'mermaid') {
                  return <Mermaid chart={String(children)} theme="dark" />
                }
                return !inline && match ? (
                  <SyntaxHighlighter style={oneDark} language={match[1]} PreTag="div" {...props}>
                    {String(children).replace(/\n$/, '')}
                  </SyntaxHighlighter>
                ) : (
                  <code className={className} {...props}>
                    {children}
                  </code>
                )
              }
            }}
          >
            {value || ''}
          </ReactMarkdown>
        )}
      </div>
    </div>
  )
}

MarkdownEditor.propTypes = {
  value: PropTypes.string,
  onChange: PropTypes.func.isRequired,
}

MarkdownEditor.defaultProps = {
  value: '',
}