package global

type ModuleParamsManager interface {
	SetSendEnabled(enable bool)
	GetSendEnabled() bool
}

type EmptyManager struct{}

func (e EmptyManager) SetSendEnabled(enable bool) {}
func (e EmptyManager) GetSendEnabled() bool       { return false }
