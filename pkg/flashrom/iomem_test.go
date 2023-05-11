package flashrom

import (
	"testing"

	"github.com/stretchr/testify/require"
)

const iomemInputRealCaseSample = `` +
	`00000000-00000fff : Reserved
00001000-0009f7ff : System RAM
0009f800-0009ffff : Reserved
000a0000-000bffff : PCI Bus 0000:00
000c0000-000c7fff : Video ROM
000f0000-000fffff : Reserved
  000f0000-000fffff : System ROM
00100000-bffdbfff : System RAM
  01000000-01e01090 : Kernel code
  01e01091-025667bf : Kernel data
  02e16000-031fffff : Kernel bss
  b7000000-beffffff : Crash kernel
bffdc000-bfffffff : Reserved
c0000000-febfffff : PCI Bus 0000:00
  feb80000-febbffff : 0000:00:02.0
  febc0000-febc0fff : 0000:00:02.0
  febc1000-febc1fff : 0000:00:03.0
  febc2000-febc2fff : 0000:00:04.0
  febec000-febeffff : 0000:00:02.0
    febec000-febeffff : virtio-pci-modern
  febf0000-febf3fff : 0000:00:03.0
    febf0000-febf3fff : virtio-pci-modern
  febf4000-febf7fff : 0000:00:04.0
    febf4000-febf7fff : virtio-pci-modern
  febf8000-febfbfff : 0000:00:05.0
    febf8000-febfbfff : virtio-pci-modern
  febfc000-febfffff : 0000:00:06.0
    febfc000-febfffff : virtio-pci-modern
fec00000-fec003ff : IOAPIC 0
fed00000-fed003ff : HPET 0
  fed00000-fed003ff : PNP0103:00
fee00000-fee00fff : Local APIC
feffc000-feffffff : Reserved
fffc0000-ffffffff : Reserved
100000000-e7fffffff : System RAM
e80000000-effffffff : PCI Bus 0000:00
`

func TestParseIOMem(t *testing.T) {
	t.Run("RealCaseSample_noerror", func(t *testing.T) {
		parsed, err := ParseIOMem([]byte(iomemInputRealCaseSample))
		require.NoError(t, err)
		require.NotNil(t, parsed)
	})
	t.Run("parsed", func(t *testing.T) {
		parsed, err := ParseIOMem([]byte(`
c0000000-febfffff : PCI Bus 0000:00
  febec000-febeffff : 0000:00:02.0
000f0000-000fffff : Reserved
  000f0000-000fffff : System ROM
`))
		require.NoError(t, err)
		require.Equal(t, IOMemEntries{
			{
				Start:       0xc0000000,
				End:         0xfebfffff,
				Description: "PCI Bus 0000:00",
				Children: IOMemEntries{
					{
						Start:       0xfebec000,
						End:         0xfebeffff,
						Description: "0000:00:02.0",
					},
				},
			},
			{
				Start:       0x000f0000,
				End:         0x000fffff,
				Description: "Reserved",
				Children: IOMemEntries{
					{
						Start:       0x000f0000,
						End:         0x000fffff,
						Description: "System ROM",
					},
				},
			},
		}, parsed)
	})
}
