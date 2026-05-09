package netem

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
)

// Controller управляет сетевой эмуляцией через tc netem.
// Требует sudo NOPASSWD для /usr/sbin/tc.
// Добавить в sudoers: user ALL=(ALL) NOPASSWD: /usr/sbin/tc
type Controller struct {
	iface string // сетевой интерфейс, например "enp0s3"
}

func New(iface string) *Controller {
	return &Controller{iface: iface}
}

// Apply применяет сетевые условия из BenchParams.
// Сначала сбрасывает предыдущие правила, потом применяет новые.
func (c *Controller) Apply(params NetParams) error {
	// Сначала сбрасываем предыдущие правила
	if err := c.reset(); err != nil {
		// Игнорируем ошибку — правил могло не быть
		log.Printf("netem reset (ignored): %v", err)
	}

	// Если все параметры нулевые — просто сбрасываем
	if params.IsEmpty() {
		log.Printf("netem: сеть без ограничений")
		return nil
	}

	// Строим команду tc
	args, err := c.buildArgs(params)
	if err != nil {
		return fmt.Errorf("build tc args: %w", err)
	}

	log.Printf("netem: применяем %s", strings.Join(args, " "))
	cmd := exec.Command("sudo", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("tc: %w, output: %s", err, out)
	}

	log.Printf("netem: применено успешно")
	return nil
}

// Reset сбрасывает все правила tc на интерфейсе
func (c *Controller) Reset() error {
	err := c.reset()
	if err != nil {
		log.Printf("netem reset (ignored): %v", err)
	}
	log.Printf("netem: правила сброшены")
	return nil
}

func (c *Controller) reset() error {
	cmd := exec.Command("sudo", "tc", "qdisc", "del", "dev", c.iface, "root")
	out, err := cmd.CombinedOutput()
	if err != nil && !strings.Contains(string(out), "No such file") {
		return fmt.Errorf("%w: %s", err, out)
	}
	return nil
}

func (c *Controller) buildArgs(params NetParams) ([]string, error) {
	// bandwidth ограничение и netem нельзя применить одновременно напрямую —
	// нужна иерархия: tbf (токен бакет) → netem (задержки/потери)
	// Но для простоты пока выбираем один режим.
	// Если задан rate — используем tbf
	// Если заданы delay/loss/jitter — используем netem
	// Если задано всё — используем netem поверх tbf через иерархию

	hasNetem := params.DelayMs > 0 || params.LossPct > 0 || params.JitterMs > 0
	hasRate := params.RateMbit > 0

	if hasRate && !hasNetem {
		// Только bandwidth ограничение
		burst := "32kbit"
		return []string{
			"tc", "qdisc", "add", "dev", c.iface,
			"root", "tbf",
			"rate", fmt.Sprintf("%.0fmbit", params.RateMbit),
			"burst", burst,
			"latency", "400ms",
		}, nil
	}

	if hasNetem && !hasRate {
		// Только netem (delay + loss + jitter)
		return c.buildNetemArgs(params), nil
	}

	if hasNetem && hasRate {
		// Комбо — пока применяем только netem, rate добавим позже
		// TODO: иерархия tbf → netem для одновременного применения
		log.Printf("netem: WARNING — bandwidth ограничение игнорируется при наличии netem параметров")
		return c.buildNetemArgs(params), nil
	}

	return nil, fmt.Errorf("нет параметров для применения")
}

func (c *Controller) buildNetemArgs(params NetParams) []string {
	args := []string{
		"tc", "qdisc", "add", "dev", c.iface,
		"root", "netem",
	}

	if params.DelayMs > 0 {
		args = append(args, "delay", fmt.Sprintf("%dms", params.DelayMs))
		if params.JitterMs > 0 {
			args = append(args,
				fmt.Sprintf("%dms", params.JitterMs),
				"distribution", "normal",
			)
		}
	}

	if params.LossPct > 0 {
		args = append(args, "loss", fmt.Sprintf("%.2f%%", params.LossPct))
	}

	return args
}

// NetParams — параметры сетевой эмуляции.
// Отдельный тип от proto.BenchParams чтобы netem пакет
// не зависел от proto пакета.
type NetParams struct {
	LossPct  float64
	DelayMs  int
	JitterMs int
	RateMbit float64
}

func (p NetParams) IsEmpty() bool {
	return p.LossPct == 0 && p.DelayMs == 0 &&
		p.JitterMs == 0 && p.RateMbit == 0
}

func (p NetParams) String() string {
	if p.IsEmpty() {
		return "baseline"
	}
	parts := []string{}
	if p.DelayMs > 0 {
		s := fmt.Sprintf("delay=%dms", p.DelayMs)
		if p.JitterMs > 0 {
			s += fmt.Sprintf("±%dms", p.JitterMs)
		}
		parts = append(parts, s)
	}
	if p.LossPct > 0 {
		parts = append(parts, fmt.Sprintf("loss=%.1f%%", p.LossPct))
	}
	if p.RateMbit > 0 {
		parts = append(parts, fmt.Sprintf("rate=%.0fmbit", p.RateMbit))
	}
	return strings.Join(parts, " ")
}
