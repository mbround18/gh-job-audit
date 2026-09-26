import { useState } from "react"
import { Check, Copy } from "lucide-react"
import { Button } from "@/components/ui/button"

export function CodeBlock({ code }: { code: string }) {
  const [copied, setCopied] = useState(false)
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(code)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch { /* clipboard unavailable */ }
  }
  return (
    <div className="relative">
      <pre className="overflow-x-auto rounded-lg bg-code p-4 pr-24 font-mono text-[13px] leading-relaxed text-code-fg"><code>{code}</code></pre>
      <Button variant="outline" size="sm" className="absolute right-2 top-2" onClick={copy} aria-label="Copy code">
        {copied ? <Check size={14} /> : <Copy size={14} />}{copied ? "Copied" : "Copy"}
      </Button>
    </div>
  )
}
