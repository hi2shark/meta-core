package nowhere

import "github.com/metacubex/mihomo/transport/nowhere/core/nw2/diagnostic"

func formatDiagnosticEvent(event diagnostic.Event) string {
	return diagnostic.FormatEvent(event)
}
