import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple

@dataclass
class GraphQLTypeRef:
    kind: str
    name: Optional[str] = None
    of_type: Optional['GraphQLTypeRef'] = None

    def get_deep_name(self) -> str:
        """Returns the scalar/object name by traversing down LIST and NON_NULL wrappers."""
        ref = self
        while ref.of_type:
            ref = ref.of_type
        return ref.name or ""

    def is_required(self) -> bool:
        """Returns True if the outer type is NON_NULL."""
        return self.kind == "NON_NULL"

    def is_list(self) -> bool:
        """Returns True if any layer is a LIST."""
        ref = self
        while ref:
            if ref.kind == "LIST":
                return True
            ref = ref.of_type
        return False

    def to_type_string(self) -> str:
        """Converts type reference to string representation e.g. [Int!]!"""
        if self.kind == "NON_NULL":
            return f"{self.of_type.to_type_string()}!" if self.of_type else "Any!"
        elif self.kind == "LIST":
            return f"[{self.of_type.to_type_string()}]" if self.of_type else "[Any]"
        else:
            return self.name or "Any"

@dataclass
class GraphQLArgument:
    name: str
    type_ref: GraphQLTypeRef
    description: Optional[str] = None
    default_value: Optional[str] = None

@dataclass
class GraphQLField:
    name: str
    type_ref: GraphQLTypeRef
    description: Optional[str] = None
    args: List[GraphQLArgument] = field(default_factory=list)

@dataclass
class GraphQLType:
    name: str
    kind: str
    description: Optional[str] = None
    fields: List[GraphQLField] = field(default_factory=list)
    input_fields: List[GraphQLArgument] = field(default_factory=list)  # For INPUT_OBJECT
    enum_values: List[str] = field(default_factory=list)

@dataclass
class GraphQLSchema:
    query_type: Optional[str] = "Query"
    mutation_type: Optional[str] = "Mutation"
    subscription_type: Optional[str] = "Subscription"
    types: Dict[str, GraphQLType] = field(default_factory=dict)

    def get_type(self, name: str) -> Optional[GraphQLType]:
        return self.types.get(name)

def parse_type_ref(data: Dict[str, Any]) -> Optional[GraphQLTypeRef]:
    if not data:
        return None
    of_type_data = data.get("ofType")
    of_type = parse_type_ref(of_type_data) if of_type_data else None
    return GraphQLTypeRef(
        kind=data.get("kind", ""),
        name=data.get("name"),
        of_type=of_type
    )

def parse_introspection(introspection_json: Dict[str, Any]) -> GraphQLSchema:
    """Parses introspection JSON into GraphQLSchema dataclass structure."""
    schema_data = introspection_json.get("data", {}).get("__schema") or introspection_json.get("__schema") or {}
    
    query_type = schema_data.get("queryType", {}).get("name") or "Query"
    mutation_type = schema_data.get("mutationType", {}).get("name") or "Mutation"
    subscription_type = schema_data.get("subscriptionType", {}).get("name") or "Subscription"
    
    types_dict = {}
    
    for type_data in schema_data.get("types", []):
        t_name = type_data.get("name")
        if not t_name or t_name.startswith("__"):
            continue  # Skip internal types
            
        t_kind = type_data.get("kind", "")
        t_desc = type_data.get("description")
        
        # Parse fields
        fields = []
        for f_data in type_data.get("fields", []) or []:
            f_name = f_data.get("name")
            f_desc = f_data.get("description")
            f_type = parse_type_ref(f_data.get("type", {}))
            
            args = []
            for a_data in f_data.get("args", []) or []:
                a_name = a_data.get("name")
                a_desc = a_data.get("description")
                a_type = parse_type_ref(a_data.get("type", {}))
                a_default = a_data.get("defaultValue")
                args.append(GraphQLArgument(name=a_name, type_ref=a_type, description=a_desc, default_value=a_default))
                
            fields.append(GraphQLField(name=f_name, type_ref=f_type, description=f_desc, args=args))
            
        # Parse inputFields
        input_fields = []
        for i_data in type_data.get("inputFields", []) or []:
            i_name = i_data.get("name")
            i_desc = i_data.get("description")
            i_type = parse_type_ref(i_data.get("type", {}))
            i_default = i_data.get("defaultValue")
            input_fields.append(GraphQLArgument(name=i_name, type_ref=i_type, description=i_desc, default_value=i_default))
            
        # Parse enum values
        enum_values = []
        for ev in type_data.get("enumValues", []) or []:
            if ev and ev.get("name"):
                enum_values.append(ev["name"])
                
        types_dict[t_name] = GraphQLType(
            name=t_name,
            kind=t_kind,
            description=t_desc,
            fields=fields,
            input_fields=input_fields,
            enum_values=enum_values
        )
        
    return GraphQLSchema(
        query_type=query_type,
        mutation_type=mutation_type,
        subscription_type=subscription_type,
        types=types_dict
    )

class QueryBuilder:
    """Generates valid GraphQL query/mutation/subscription strings with selection sets up to N depth."""
    def __init__(self, schema: GraphQLSchema):
        self.schema = schema

    def generate_field_selection(self, type_name: str, max_depth: int, current_depth: int = 1, visited: List[str] = None) -> str:
        """Recursively builds selection set for an object type name."""
        if visited is None:
            visited = []
            
        gtype = self.schema.get_type(type_name)
        if not gtype or not gtype.fields or current_depth > max_depth:
            return ""
            
        # Check recursion
        if type_name in visited:
            # Allow limited recursion but stop at depth limit to prevent infinite loops
            recursion_count = visited.count(type_name)
            if recursion_count >= 2:
                return ""

        visited = visited + [type_name]
        selections = []
        
        for field in gtype.fields:
            field_deep_type = field.type_ref.get_deep_name()
            field_type_info = self.schema.get_type(field_deep_type)
            
            if field_type_info and field_type_info.kind in ("OBJECT", "INTERFACE", "UNION"):
                # Nested selection
                nested = self.generate_field_selection(field_deep_type, max_depth, current_depth + 1, visited)
                if nested:
                    selections.append(f"{field.name} {nested}")
            else:
                # Scalar/Enum/Interface/Union with no fields (or skipped)
                selections.append(field.name)
                
        if not selections:
            return ""
            
        return "{\n  " + "\n  ".join(selections).replace("\n", "\n  ") + "\n}"

    def build_operation(
        self, 
        operation_type: str, 
        field: GraphQLField, 
        max_depth: int = 3
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Builds a full operation (query/mutation/subscription) string and sample variables.
        Example output:
        query($id: ID!) {
          user(id: $id) {
            id
            name
          }
        }
        variables: {"id": "1"}
        """
        op_name = operation_type.lower()
        var_defs = []
        var_values = {}
        field_args = []
        
        # Build arguments & variables
        for arg in field.args:
            var_name = f"{field.name}_{arg.name}"
            var_defs.append(f"${var_name}: {arg.type_ref.to_type_string()}")
            field_args.append(f"{arg.name}: ${var_name}")
            
            # Generate sample value
            var_values[var_name] = self.generate_sample_value(arg.type_ref, arg.name)
            
        var_def_str = f"({', '.join(var_defs)})" if var_defs else ""
        arg_str = f"({', '.join(field_args)})" if field_args else ""
        
        # Build selection set
        field_deep_type = field.type_ref.get_deep_name()
        selection = self.generate_field_selection(field_deep_type, max_depth)
        
        if not selection:
            # If it's a scalar return type, no selection set is allowed/needed in GraphQL
            query_str = f"{op_name}{var_def_str} {{\n  {field.name}{arg_str}\n}}"
        else:
            query_str = f"{op_name}{var_def_str} {{\n  {field.name}{arg_str} {selection}\n}}"
            
        return query_str, var_values

    def generate_sample_value(self, type_ref: GraphQLTypeRef, arg_name: str) -> Any:
        """Generates a smart default/fuzzed sample value for the argument type."""
        deep_name = type_ref.get_deep_name().upper()
        
        # Determine base scalar/enum default
        val = None
        if "INT" in deep_name:
            if "limit" in arg_name or "size" in arg_name:
                val = 10
            elif "offset" in arg_name or "skip" in arg_name:
                val = 0
            else:
                val = 1
        elif "FLOAT" in deep_name:
            val = 1.0
        elif "BOOLEAN" in deep_name:
            val = True
        elif "ID" in deep_name:
            val = "1"
        elif "STRING" in deep_name:
            if "email" in arg_name:
                val = "test@example.com"
            elif "url" in arg_name or "webhook" in arg_name:
                val = "http://127.0.0.1:8000"
            elif "password" in arg_name:
                val = "Password123!"
            else:
                val = "test_value"
        else:
            # Check if it's an enum or input object in schema
            gtype = self.schema.get_type(type_ref.get_deep_name())
            if gtype:
                if gtype.kind == "ENUM" and gtype.enum_values:
                    val = gtype.enum_values[0]
                elif gtype.kind == "INPUT_OBJECT":
                    input_val = {}
                    for field in gtype.input_fields:
                        input_val[field.name] = self.generate_sample_value(field.type_ref, field.name)
                    val = input_val
            
            if val is None:
                val = "sample_scalar"

        if type_ref.is_list():
            return [val]
        return val
