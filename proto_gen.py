import sys
import os
import shutil
import tempfile
import importlib.util
import random
from google.protobuf import descriptor
from google.protobuf.json_format import MessageToJson
from grpc_tools import protoc

def generate_dummy_data(message_descriptor, message_instance):
    """
    Recursively fills a protobuf message instance with dummy data based on its descriptor.
    """
    for field in message_descriptor.fields:
        # Skip if field is already set (for oneof cases, usually)
        # But for generating a full template, we want to try setting everything.
        
        # 1. Handle Repeated Fields (Lists)
        if field.label == descriptor.FieldDescriptor.LABEL_REPEATED:
            # Add one item to the list so we can see the structure
            if field.type == descriptor.FieldDescriptor.TYPE_MESSAGE:
                sub_msg = getattr(message_instance, field.name).add()
                generate_dummy_data(field.message_type, sub_msg)
            elif field.type == descriptor.FieldDescriptor.TYPE_STRING:
                getattr(message_instance, field.name).append("sample_string")
            elif field.type in [descriptor.FieldDescriptor.TYPE_INT32, descriptor.FieldDescriptor.TYPE_INT64]:
                getattr(message_instance, field.name).append(123)
            elif field.type == descriptor.FieldDescriptor.TYPE_BOOL:
                getattr(message_instance, field.name).append(True)
            continue

        # 2. Handle Nested Messages
        if field.type == descriptor.FieldDescriptor.TYPE_MESSAGE:
            sub_msg = getattr(message_instance, field.name)
            generate_dummy_data(field.message_type, sub_msg)
        
        # 3. Handle Primitives
        elif field.type == descriptor.FieldDescriptor.TYPE_STRING:
            setattr(message_instance, field.name, f"{field.name}_value")
            
        elif field.type == descriptor.FieldDescriptor.TYPE_BOOL:
            setattr(message_instance, field.name, True)
            
        elif field.type in [descriptor.FieldDescriptor.TYPE_INT32, descriptor.FieldDescriptor.TYPE_INT64, 
                            descriptor.FieldDescriptor.TYPE_UINT32, descriptor.FieldDescriptor.TYPE_UINT64]:
            setattr(message_instance, field.name, 12345)
            
        elif field.type == descriptor.FieldDescriptor.TYPE_FLOAT:
            setattr(message_instance, field.name, 12.34)
            
        elif field.type == descriptor.FieldDescriptor.TYPE_ENUM:
            # Pick the first non-zero value if possible, else 0
            enum_desc = field.enum_type
            if len(enum_desc.values) > 1:
                setattr(message_instance, field.name, enum_desc.values[1].number)
            else:
                setattr(message_instance, field.name, enum_desc.values[0].number)

def main():
    if len(sys.argv) < 3:
        print("Usage: python proto_gen.py <path_to_proto_file> <MessageName>")
        sys.exit(1)

    proto_path = sys.argv[1]
    message_name = sys.argv[2]
    
    if not os.path.exists(proto_path):
        print(f"Error: File {proto_path} not found.")
        sys.exit(1)

    proto_dir = os.path.dirname(os.path.abspath(proto_path))
    proto_file = os.path.basename(proto_path)
    
    # Create a temp dir to compile the python module
    with tempfile.TemporaryDirectory() as temp_dir:
        # Copy proto file to temp dir to avoid polluting source dir
        shutil.copy(proto_path, os.path.join(temp_dir, proto_file))
        
        # Run protoc
        # We include the original directory in proto_path so imports work
        protoc_args = [
            'grpc_tools.protoc',
            f'-I{temp_dir}',
            f'-I{proto_dir}', 
            f'--python_out={temp_dir}',
            os.path.join(temp_dir, proto_file)
        ]
        
        if protoc.main(protoc_args) != 0:
            print("Error: protoc compilation failed.")
            sys.exit(1)

        # Import the generated module dynamically
        generated_file_name = proto_file.replace('.proto', '_pb2.py')
        module_path = os.path.join(temp_dir, generated_file_name)
        
        spec = importlib.util.spec_from_file_location("generated_proto", module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        # Find the message class
        if not hasattr(module, message_name):
            print(f"Error: Message '{message_name}' not found in {proto_file}")
            print("Available messages:", [x for x in dir(module) if isinstance(getattr(module, x), type)])
            sys.exit(1)
            
        MessageClass = getattr(module, message_name)
        instance = MessageClass()
        
        # Populate
        generate_dummy_data(instance.DESCRIPTOR, instance)
        
        # Output JSON
        print(MessageToJson(instance, preserving_proto_field_name=True))

if __name__ == "__main__":
    main()
