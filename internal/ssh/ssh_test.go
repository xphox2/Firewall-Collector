package ssh

import "testing"

func TestCleanOutput(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty output",
			input:    "",
			expected: "",
		},
		{
			name:     "only_config_output",
			input:    "config system global\nset hostname \"fw\"\nend",
			expected: "config system global\nset hostname \"fw\"\nend",
		},
		{
			name:     "more_prompt_removed",
			input:    "config system global\n--More--\nend",
			expected: "config system global\nend",
		},
		{
			name:     "dollar_sign_in_config_preserved",
			input:    "config system global\nset alias \"FortiGate-100E$\"\nset admin-login-max 100\nend",
			expected: "config system global\nset alias \"FortiGate-100E$\"\nset admin-login-max 100\nend",
		},
		{
			name:     "command_echo_preserved_dollar_prompt_filtered",
			input:    "FW-100E $ config system global\nset alias \"test\"\nFW-100E #",
			expected: "FW-100E $ config system global\nset alias \"test\"",
		},
		{
			name:     "FGT_prompts_removed",
			input:    "FGT-100E #\nconfig\nset hostname \"fw\"\nFGT-100E $",
			expected: "config\nset hostname \"fw\"",
		},
		{
			name:     "FG_prompts_removed",
			input:    "FG-100E #\nconfig\nset hostname \"fw\"\nFG-100E #",
			expected: "config\nset hostname \"fw\"",
		},
		{
			name:     "VDOM_prompt_command_filtered",
			input:    "FW-100E (global) # config\nset hostname \"fw\"\nFW-100E (root) $",
			expected: "FW-100E (global) # config\nset hostname \"fw\"",
		},
		{
			name:     "empty_lines_and_prompt_removed",
			input:    "FW-100E #\n\n\nconfig\n\n\nend\n\n\n",
			expected: "config\nend",
		},
		{
			name:     "diagnose_sys_csum",
			input:    "FW-100E # diagnose sys csum\nimage: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4\nFW-100E #",
			expected: "FW-100E # diagnose sys csum\nimage: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
		},
		{
			name:     "Run_Time_preserved",
			input:    "Run Time: 12:34:56\nTemperature: 45C",
			expected: "Run Time: 12:34:56\nTemperature: 45C",
		},
		{
			name:     "config_with_dollar_in_string_value",
			input:    "config firewall address\nedit \"Blocked-Host$\"\nset subnet 192.168.1.100 255.255.255.255\nnext\nend",
			expected: "config firewall address\nedit \"Blocked-Host$\"\nset subnet 192.168.1.100 255.255.255.255\nnext\nend",
		},
		{
			name:     "full_config_show_with_echo",
			input:    "FW-100E # show full-configuration\nconfig system global\nset hostname \"TestFirewall\"\nend\nFW-100E #",
			expected: "FW-100E # show full-configuration\nconfig system global\nset hostname \"TestFirewall\"\nend",
		},
		{
			name:     "pure_prompts_removed",
			input:    "FW-100E #\nFW-100E #",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cleanOutput(tt.input)
			if result != tt.expected {
				t.Errorf("cleanOutput() = \n%q\nwant:\n%q", result, tt.expected)
			}
		})
	}
}

func TestTrimToConfigHeader(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "prompt_glued_to_header_stripped",
			input:    "FW-HOME # #config-version=FGT60F-7.4.12-FW-build2902-260505:opmode=0\n#conf_file_ver=123\nconfig system global\nset hostname \"FW-HOME\"\nend",
			expected: "#config-version=FGT60F-7.4.12-FW-build2902-260505:opmode=0\n#conf_file_ver=123\nconfig system global\nset hostname \"FW-HOME\"\nend",
		},
		{
			name:     "already_clean_unchanged",
			input:    "#config-version=FGT60F-7.4.12\nconfig system global\nend",
			expected: "#config-version=FGT60F-7.4.12\nconfig system global\nend",
		},
		{
			name:     "no_header_returned_as_is",
			input:    "config system global\nset hostname \"x\"\nend",
			expected: "config system global\nset hostname \"x\"\nend",
		},
		{
			name:     "later_inline_occurrence_not_split",
			input:    "#config-version=A\nconfig log setting\nset custom \"see #config-version= note\"\nend",
			expected: "#config-version=A\nconfig log setting\nset custom \"see #config-version= note\"\nend",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := trimToConfigHeader(tt.input); got != tt.expected {
				t.Errorf("trimToConfigHeader() =\n%q\nwant:\n%q", got, tt.expected)
			}
		})
	}
}

func TestIsCLIPrompt(t *testing.T) {
	tests := []struct {
		line     string
		expected bool
	}{
		{"FW-100E #", true},
		{"FW-100E $", true},
		{"FGT-100E #", true},
		{"FGT-100E $", true},
		{"FG-100E #", true},
		{"FG-100E $", true},
		{"FW-100E (global) #", true},
		{"FW-100E (global) $", true},
		{"FW-100E (root) #", true},
		{"FW-100E (root) $", true},
		{"FW-100E # ", true},
		{"FW-100E $ ", true},
		{"FGT-100E # ", true},
		{"FGT-100E $ ", true},
		{"FG-100E # ", true},
		{"FG-100E $ ", true},
		{"FW-100E (global) # ", true},
		{"FW-100E (global) $ ", true},
		{"FW-100E (root) # ", true},
		{"FW-100E (root) $ ", true},
		{"set alias \"FortiGate-100E$\"", false},
		{"config system global", false},
		{"image: a1b2c3d4", false},
		{"Run Time: 12:34:56", false},
		{"Temperature: 45C", false},
		{"hostname$", false},
		{"FW-100E", false},
		{"FW-100E#", false},
		{"FW-100E$", false},
		{"FW-100E #foo", false},
		{"Some random text", false},
		{"", false},
		{"FW-100E # show full-configuration", false},
		{"FW-100E $ get system status", false},
	}

	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			result := isCLIPrompt(tt.line)
			if result != tt.expected {
				t.Errorf("isCLIPrompt(%q) = %v, want %v", tt.line, result, tt.expected)
			}
		})
	}
}
