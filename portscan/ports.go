package portscan

const (
	minPort = 1
	maxPort = 65535
)

type PortSet struct {
	items []portItem
}

type portItemKind int

const (
	portItemRange portItemKind = iota
	portItemList
)

type portItem struct {
	kind portItemKind

	from int
	to   int

	ports []int
}

func Range(start, end int) PortSet {
	return PortSet{
		items: []portItem{{
			kind: portItemRange,
			from: start,
			to:   end,
		}},
	}
}

func Ports(list ...int) PortSet {
	cp := make([]int, len(list))
	copy(cp, list)
	return PortSet{
		items: []portItem{{
			kind:  portItemList,
			ports: cp,
		}},
	}
}

func Join(sets ...PortSet) PortSet {
	var items []portItem
	for _, set := range sets {
		items = append(items, set.items...)
	}
	return PortSet{items: items}
}

func validPort(port int) bool {
	return port >= minPort && port <= maxPort
}

func (ps PortSet) validateAndExpand() ([]uint16, error) {
	if len(ps.items) == 0 {
		return nil, nil
	}

	uniq := make(map[uint16]struct{}, 64)

	for _, item := range ps.items {
		switch item.kind {
		case portItemRange:
			from, to := item.from, item.to
			if from > to {
				from, to = to, from
			}

			if !validPort(from) {
				return nil, PortError{Kind: "range_start", Value: from}
			}
			if !validPort(to) {
				return nil, PortError{Kind: "range_end", Value: to}
			}

			for port := from; port <= to; port++ {
				// дедупликация: в uniq остаются только уникальные порты
				uniq[uint16(port)] = struct{}{}
			}
		case portItemList:
			for _, port := range item.ports {
				if !validPort(port) {
					return nil, PortError{Kind: "port", Value: port}
				}
				// дедупликация списка портов
				uniq[uint16(port)] = struct{}{}
			}
		default:
			return nil, ErrUnknownPortItem
		}
	}

	out := make([]uint16, len(uniq))
	i := 0
	for port := range uniq {
		out[i] = port
		i++
	}
	return out, nil
}

type PortError struct {
	Kind  string
	Value int
}

func (e PortError) Error() string {
	return "invalid port " + e.Kind
}
