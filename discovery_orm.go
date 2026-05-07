package gmcore_transport

import (
	"fmt"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type transportPeerModel struct {
	Name     string `gorm:"primaryKey"`
	Host     string
	Port     int
	Status   string
	LastSeen int64
	Secret   []byte `gorm:"type:blob"`
}

func (transportPeerModel) TableName() string {
	return "transport_peers"
}

type ORMDiscoveryBackend struct {
	db    *gorm.DB
	table string
}

func NewORMDiscoveryBackend(db *gorm.DB, table string) (*ORMDiscoveryBackend, error) {
	if table == "" {
		table = "transport_peers"
	}

	backend := &ORMDiscoveryBackend{db: db, table: table}

	if err := db.Table(table).AutoMigrate(&transportPeerModel{}); err != nil {
		return nil, fmt.Errorf("gmcore-transport: failed to migrate %s: %w", table, err)
	}

	return backend, nil
}

func (b *ORMDiscoveryBackend) Save(peer Peer) error {
	tp := transportPeerModel{
		Name:     peer.Name,
		Host:     peer.Host,
		Port:     peer.Port,
		Status:   peer.Status,
		LastSeen: time.Now().Unix(),
		Secret:   peer.Secret,
	}
	return b.db.Table(b.table).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "name"}},
		UpdateAll: true,
	}).Create(&tp).Error
}

func (b *ORMDiscoveryBackend) Load(name string) (Peer, error) {
	var tp transportPeerModel
	if err := b.db.Table(b.table).Where("name = ?", name).First(&tp).Error; err != nil {
		return Peer{}, fmt.Errorf("gmcore-transport: peer %q not found", name)
	}
	return Peer{
		Name:     tp.Name,
		Host:     tp.Host,
		Port:     tp.Port,
		Status:   tp.Status,
		LastSeen: tp.LastSeen,
		Secret:   tp.Secret,
	}, nil
}

func (b *ORMDiscoveryBackend) List() ([]Peer, error) {
	var tps []transportPeerModel
	if err := b.db.Table(b.table).Find(&tps).Error; err != nil {
		return nil, fmt.Errorf("gmcore-transport: failed to list peers: %w", err)
	}

	peers := make([]Peer, 0, len(tps))
	for _, tp := range tps {
		peers = append(peers, Peer{
			Name:     tp.Name,
			Host:     tp.Host,
			Port:     tp.Port,
			Status:   tp.Status,
			LastSeen: tp.LastSeen,
			Secret:   tp.Secret,
		})
	}
	return peers, nil
}

func (b *ORMDiscoveryBackend) Delete(name string) error {
	return b.db.Table(b.table).Where("name = ?", name).Delete(&transportPeerModel{}).Error
}

func (b *ORMDiscoveryBackend) Close() error {
	sqlDB, err := b.db.DB()
	if err != nil {
		return fmt.Errorf("gmcore-transport: failed to get underlying DB: %w", err)
	}
	return sqlDB.Close()
}
