package portscan

import (
	"errors"
	"sort"
)

type PortSet struct {
	items []portItem
}

type portItemKind uint8

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
	for _, s := range sets {
		items = append(items, s.items...)
	}
	return PortSet{items: items}
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

			if from < 1 || from > 65535 {
				return nil, &PortError{Kind: "range_start", Value: from}
			}
			if to < 1 || to > 65535 {
				return nil, &PortError{Kind: "range_end", Value: to}
			}

			for p := from; p <= to; p++ {
				// дедупликация: в uniq остаются только уникальные порты
				uniq[uint16(p)] = struct{}{}
			}
		case portItemList:
			for _, p := range item.ports {
				if p < 1 || p > 65535 {
					return nil, &PortError{Kind: "port", Value: p}
				}
				// дедупликация списка портов
				uniq[uint16(p)] = struct{}{}
			}
		default:
			return nil, errors.New("unknown port item kind")
		}
	}

	out := make([]uint16, 0, len(uniq))
	for p := range uniq {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

type PortError struct {
	Kind  string
	Value int
}

func (e *PortError) Error() string {
	return "invalid port " + e.Kind
}
