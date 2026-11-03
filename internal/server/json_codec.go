package server

import (
	"github.com/go-kratos/kratos/v3/encoding"
	"github.com/mengbin92/user-center/pkg/jsonx"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// Kratos v3's standard JSON codec does not implement the Protobuf JSON
// contract: int64 values become numbers and string int64 inputs fail. Keep
// the transport in agreement with the generated OpenAPI/TypeScript schema.
type wireJSONCodec struct{}

func init()                        { encoding.RegisterCodec(wireJSONCodec{}) }
func (wireJSONCodec) Name() string { return "json" }
func (wireJSONCodec) Marshal(value any) ([]byte, error) {
	if message, ok := value.(proto.Message); ok {
		return (protojson.MarshalOptions{UseProtoNames: true, EmitUnpopulated: true}).Marshal(message)
	}
	return jsonx.Marshal(value)
}
func (wireJSONCodec) Unmarshal(data []byte, value any) error {
	if len(data) == 0 {
		return nil
	}
	if message, ok := value.(proto.Message); ok {
		return protojson.Unmarshal(data, message)
	}
	return jsonx.Unmarshal(data, value)
}
