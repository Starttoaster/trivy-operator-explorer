package snapshot

import (
	"log"
	"strings"
	"sync"
	"time"

	"github.com/chia-network/go-modules/pkg/slogs"
	"github.com/starttoaster/trivy-operator-explorer/internal/db"
	"github.com/starttoaster/trivy-operator-explorer/internal/kube"
	complianceview "github.com/starttoaster/trivy-operator-explorer/internal/web/views/compliance"
	imagesview "github.com/starttoaster/trivy-operator-explorer/internal/web/views/images"
	indexview "github.com/starttoaster/trivy-operator-explorer/internal/web/views/index"
)

// Start begins background goroutines that keep records synced to the DB
func Start() {
	go run()
}

func run() {
	var snapshotMu sync.Mutex
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	doSnapshot := func() {
		snapshotMu.Lock()
		defer snapshotMu.Unlock()

		today := time.Now()
		exists, err := db.HasVulnerabilityCountForDate(today)
		log.Println("Vulnerability count exists for today")
		if err != nil {
			slogs.Logr.Error("failed to check if vulnerability count exists for today", "error", err.Error())
			return
		}
		if exists {
			return
		}
		vulnList, err := kube.GetVulnerabilityReportList()
		if err != nil {
			slogs.Logr.Error("failed to get vulnerability reports for daily snapshot", "error", err.Error())
			return
		}
		imagesView := imagesview.GetView(vulnList, nil, imagesview.Filters{})
		indexData := indexview.GetView(imagesView, complianceview.View{})
		row := db.VulnerabilitiesBySeverity{
			DateTime: today,
			Critical: uint32(indexData.CriticalVulnerabilities),
			High:     uint32(indexData.HighVulnerabilities),
			Medium:   uint32(indexData.MediumVulnerabilities),
			Low:      uint32(indexData.LowVulnerabilities),
			Unknown:  0,
		}
		if err := db.InsertVulnerabilitiesCount(row); err != nil {
			if strings.Contains(err.Error(), "UNIQUE constraint") {
				slogs.Logr.Debug("vulnerability count for today already exists (concurrent insert)")
				return
			}
			slogs.Logr.Error("failed to insert daily vulnerability count", "error", err.Error())
			return
		}
		slogs.Logr.Info("recorded daily vulnerability count snapshot", "date", today.Format("2006-01-02"))
	}

	doSnapshot()
	for range ticker.C {
		doSnapshot()
	}
}
