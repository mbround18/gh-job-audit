import { Archive, BellRing, BookMarked, CalendarClock, Database, GitBranch, Mail, MousePointerClick, PowerOff, ShieldCheck, Undo2 } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardTitle } from "@/components/ui/card"
import { CodeBlock } from "@/components/code-block"

const features = [
  { icon: CalendarClock, title: "Weekly repo audit", body: "Checks every repo against configurable thresholds: idle days, popular score, CI runs, private minutes and bot churn." },
  { icon: BellRing, title: "Actions-usage alerts", body: "Get warned at 50%, 75% and 90% of your monthly Actions quota, before the bill surprises you." },
  { icon: Database, title: "Stored in Postgres", body: "Every recommendation is persisted, so decisions and history survive restarts and upgrades." },
  { icon: Mail, title: "Email delivery", body: "Reports arrive via Resend or plain SMTP, whichever you already have." },
]

const security = [
  "Default-deny middleware",
  "Owner-only GitHub sign-in, matched by numeric GitHub user id",
  "Single-use, hashed tokens",
  "CSRF and origin checks",
  "Short-lived sessions",
  "Strict CSP and security headers",
  "Rate limiting",
]

const step1 = `# GitHub App settings
Permissions:
  Administration: Read & write
  Actions:        Read
  Metadata:       Read
Callback URL: https://YOUR_HOST/callback
# then: Generate a private key (saves app.pem)`

const step2 = `kubectl create secret generic gh-job-audit-github-app \\
  --from-literal=app-id=... --from-literal=client-id=... \\
  --from-literal=client-secret=... --from-file=private-key=app.pem

kubectl create secret generic gh-job-audit-mail \\
  --from-literal=resend-api-key=...

kubectl create secret generic gh-job-audit-session \\
  --from-literal=session-secret=$(openssl rand -hex 32)`

const step3 = `helm repo add mbround18 https://mbround18.github.io/helm-charts
helm install gh-job-audit mbround18/gh-job-audit \\
  --set owner=YOUR_LOGIN \\
  --set baseUrl=https://YOUR_HOST \\
  --set mail.to=you@example.com \\
  --set mail.from=audit@example.com`

function Section({ id, title, children }: { id: string; title: string; children: React.ReactNode }) {
  return (
    <section id={id} className="mt-20">
      <h2 className="mb-6 text-2xl font-bold tracking-tight">{title}</h2>
      {children}
    </section>
  )
}

export default function App() {
  return (
    <div className="mx-auto max-w-4xl px-4 py-16 sm:px-6">
      <header>
        <Badge className="mb-4"><GitBranch size={12} className="mr-1" /> Self-hosted, Kubernetes-native</Badge>
        <h1 className="font-mono text-4xl font-bold tracking-tight sm:text-6xl">gh-job-audit</h1>
        <p className="mt-4 max-w-2xl text-lg text-muted-foreground">
          A weekly GitHub audit that emails you what to archive, what to switch off, and lets you do it with one signed-in click.
        </p>
        <div className="mt-6 flex flex-wrap gap-3">
          <Button asChild><a href="#deploy">Deploy it yourself</a></Button>
          <Button asChild variant="outline"><a href="https://github.com/mbround18/helm-charts"><GitBranch size={16} /> Helm charts</a></Button>
        </div>
      </header>

      <Section id="what" title="What it does">
        <div className="grid gap-4 sm:grid-cols-2">
          {features.map(({ icon: Icon, title, body }) => (
            <Card key={title}>
              <CardTitle><Icon size={18} className="text-primary" />{title}</CardTitle>
              <CardContent>{body}</CardContent>
            </Card>
          ))}
        </div>
      </Section>

      <Section id="magic" title="The magic: buttons in the email">
        <p className="mb-4 text-muted-foreground">
          Each recommendation in the email carries single-use, expiring buttons.
        </p>
        <div className="mb-6 flex flex-wrap gap-2">
          <Button variant="outline" tabIndex={-1} aria-hidden><Archive size={16} /> Archive repo</Button>
          <Button variant="outline" tabIndex={-1} aria-hidden><PowerOff size={16} /> Turn off Actions</Button>
          <Button variant="outline" tabIndex={-1} aria-hidden><Undo2 size={16} /> Keep as-is</Button>
        </div>
        <Card className="mb-6">
          <CardTitle><MousePointerClick size={18} className="text-primary" />What happens on click</CardTitle>
          <CardContent>
            Clicking requires signing in with GitHub as the configured owner. The confirm page states exactly what will happen.
            The action is then queued on NATS JetStream and executed by a worker, and everything is audit-logged.
          </CardContent>
        </Card>
        <Card>
          <CardTitle><ShieldCheck size={18} className="text-primary" />Security model</CardTitle>
          <ul className="list-disc space-y-1 pl-5 text-sm text-muted-foreground">
            {security.map((s) => <li key={s}>{s}</li>)}
          </ul>
        </Card>
      </Section>

      <Section id="deploy" title="Deploy it yourself">
        <div className="space-y-8">
          <div>
            <h3 className="mb-2 font-semibold">1. Create a GitHub App</h3>
            <CodeBlock code={step1} />
          </div>
          <div>
            <h3 className="mb-2 font-semibold">2. Create the secrets</h3>
            <CodeBlock code={step2} />
            <p className="mt-2 text-sm text-muted-foreground">
              The database secret is a Postgres URI secret with key <code className="font-mono">uri</code>; CloudNativePG's <code className="font-mono">&lt;cluster&gt;-app</code> secret works.
            </p>
          </div>
          <div>
            <h3 className="mb-2 font-semibold">3. Install the chart</h3>
            <CodeBlock code={step3} />
            <p className="mt-2 text-sm text-muted-foreground">
              The chart bundles NATS with JetStream (<code className="font-mono">nats.enabled=true</code> by default).
            </p>
          </div>
          <div>
            <h3 className="mb-2 font-semibold">4. Tune it</h3>
            <p className="text-sm text-muted-foreground">
              Thresholds are values under <code className="font-mono">thresholds:</code>. The report runs weekly, controlled by the <code className="font-mono">report.schedule</code> cron.
            </p>
          </div>
        </div>
      </Section>

      <footer className="mt-20 flex flex-wrap items-center gap-x-6 gap-y-2 border-t border-border pt-6 text-sm text-muted-foreground">
        <a className="inline-flex items-center gap-1 hover:text-foreground" href="https://github.com/mbround18/helm-charts"><GitBranch size={14} /> mbround18/helm-charts</a>
        <a className="inline-flex items-center gap-1 hover:text-foreground" href="https://hub.docker.com/r/mbround18/gh-job-audit"><BookMarked size={14} /> Docker Hub: mbround18/gh-job-audit</a>
      </footer>
    </div>
  )
}
