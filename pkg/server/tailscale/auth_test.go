package tailscale

import "testing"

func Test_isInTailscaleNet(t *testing.T) {
	type args struct {
		ipstr string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "local",
			args: args{
				ipstr: "127.0.0.1",
			},
			want: false,
		},
		{
			name: "tailnet",
			args: args{
				ipstr: "100.123.123.123",
			},
			want: true,
		},
		{
			name: "not tailnet",
			args: args{
				ipstr: "123.123.123.123",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isInTailscaleNet(tt.args.ipstr); got != tt.want {
				t.Errorf("isInTailscaleNet() = %v, want %v", got, tt.want)
			}
		})
	}
}
