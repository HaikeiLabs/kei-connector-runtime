// Copyright 2026 Haikei Labs
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package policybundle

import "strings"

// MatchRenderedResource reports whether rendered is the rendered form of
// template. The template is a slash-separated path whose {var} parts match
// exactly one non-empty path segment each; a variable segment must contain
// no '/', no encoded slash (%2F or %2f) and must not be '.' or '..'. Every
// literal part of the template (including a scheme prefix such as
// "github:repo/") must match the rendered segment exactly. The template and
// the rendered resource must have the same number of segments.
func MatchRenderedResource(template, rendered string) bool {
	if template == "" || rendered == "" {
		return false
	}
	templateParts := strings.Split(template, "/")
	renderedParts := strings.Split(rendered, "/")
	if len(templateParts) != len(renderedParts) {
		return false
	}
	for i, tp := range templateParts {
		rp := renderedParts[i]
		if strings.HasPrefix(tp, "{") && strings.HasSuffix(tp, "}") {
			if rp == "" || rp == "." || rp == ".." ||
				strings.Contains(rp, "%2F") || strings.Contains(rp, "%2f") {
				return false
			}
			continue
		}
		if tp != rp {
			return false
		}
	}
	return true
}
