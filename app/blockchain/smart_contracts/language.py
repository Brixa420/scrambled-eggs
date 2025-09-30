""
Brixa Smart Contract Language (BSCL)

Defines the high-level language for writing Brixa smart contracts
and the compiler that transforms it into bytecode.
"""
import ast
import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple, Union

# Token types for the lexer
class TokenType(Enum):
    # Single-character tokens
    LEFT_PAREN = '('
    RIGHT_PAREN = ')'
    LEFT_BRACE = '{'
    RIGHT_BRACE = '}'
    COMMA = ','
    DOT = '.'
    MINUS = '-'
    PLUS = '+'
    SEMICOLON = ';'
    SLASH = '/'
    STAR = '*'
    MODULO = '%'
    
    # One or two character tokens
    BANG = '!'
    BANG_EQUAL = '!='
    EQUAL = '='
    EQUAL_EQUAL = '=='
    GREATER = '>'
    GREATER_EQUAL = '>='
    LESS = '<'
    LESS_EQUAL = '<='
    
    # Literals
    IDENTIFIER = 'IDENTIFIER'
    STRING = 'STRING'
    NUMBER = 'NUMBER'
    
    # Keywords
    AND = 'and'
    OR = 'or'
    NOT = 'not'
    IF = 'if'
    ELSE = 'else'
    FOR = 'for'
    WHILE = 'while'
    FUNCTION = 'function'
    RETURN = 'return'
    VAR = 'var'
    CONST = 'const'
    IMPORT = 'import'
    CONTRACT = 'contract'
    EVENT = 'event'
    EMIT = 'emit'
    MAPPING = 'mapping'
    ADDRESS = 'address'
    UINT = 'uint'
    BOOL = 'bool'
    STR = 'string'
    BYTES = 'bytes'
    
    # End of file
    EOF = 'EOF'

@dataclass
class Token:
    """Represents a single token in the source code."""
    type: TokenType
    lexeme: str
    literal: Any
    line: int
    
    def __str__(self) -> str:
        return f"{self.type} {self.lexeme} {self.literal}"

class Scanner:
    """Lexical scanner that converts source code into tokens."""
    
    keywords = {
        'and': TokenType.AND,
        'or': TokenType.OR,
        'not': TokenType.NOT,
        'if': TokenType.IF,
        'else': TokenType.ELSE,
        'for': TokenType.FOR,
        'while': TokenType.WHILE,
        'function': TokenType.FUNCTION,
        'return': TokenType.RETURN,
        'var': TokenType.VAR,
        'const': TokenType.CONST,
        'import': TokenType.IMPORT,
        'contract': TokenType.CONTRACT,
        'event': TokenType.EVENT,
        'emit': TokenType.EMIT,
        'mapping': TokenType.MAPPING,
        'address': TokenType.ADDRESS,
        'uint': TokenType.UINT,
        'bool': TokenType.BOOL,
        'string': TokenType.STR,
        'bytes': TokenType.BYTES,
    }
    
    def __init__(self, source: str):
        self.source = source
        self.tokens: List[Token] = []
        self.start = 0
        self.current = 0
        self.line = 1
    
    def scan_tokens(self) -> List[Token]:
        """Scan the source code and return a list of tokens."""
        while not self.is_at_end():
            self.start = self.current
            self.scan_token()
        
        self.tokens.append(Token(TokenType.EOF, "", None, self.line))
        return self.tokens
    
    def scan_token(self) -> None:
        """Scan a single token."""
        c = self.advance()
        
        # Single-character tokens
        if c == '(': self.add_token(TokenType.LEFT_PAREN)
        elif c == ')': self.add_token(TokenType.RIGHT_PAREN)
        elif c == '{': self.add_token(TokenType.LEFT_BRACE)
        elif c == '}': self.add_token(TokenType.RIGHT_BRACE)
        elif c == ',': self.add_token(TokenType.COMMA)
        elif c == '.': self.add_token(TokenType.DOT)
        elif c == '-': self.add_token(TokenType.MINUS)
        elif c == '+': self.add_token(TokenType.PLUS)
        elif c == ';': self.add_token(TokenType.SEMICOLON)
        elif c == '*': self.add_token(TokenType.STAR)
        elif c == '%': self.add_token(TokenType.MODULO)
        
        # One or two character tokens
        elif c == '!':
            self.add_token(TokenType.BANG_EQUAL if self.match('=') else TokenType.BANG)
        elif c == '=':
            self.add_token(TokenType.EQUAL_EQUAL if self.match('=') else TokenType.EQUAL)
        elif c == '<':
            self.add_token(TokenType.LESS_EQUAL if self.match('=') else TokenType.LESS)
        elif c == '>':
            self.add_token(TokenType.GREATER_EQUAL if self.match('=') else TokenType.GREATER)
        
        # Comments
        elif c == '/':
            if self.match('/'):
                # A comment goes until the end of the line
                while self.peek() != '\n' and not self.is_at_end():
                    self.advance()
            else:
                self.add_token(TokenType.SLASH)
        
        # Whitespace
        elif c in ' \r\t':
            pass  # Ignore whitespace
        elif c == '\n':
            self.line += 1
        
        # String literals
        elif c == '"':
            self.string()
        
        # Numbers
        elif c.isdigit():
            self.number()
        
        # Identifiers
        elif c.isalpha() or c == '_':
            self.identifier()
        
        else:
            raise SyntaxError(f"Unexpected character: {c} at line {self.line}")
    
    def identifier(self) -> None:
        """Scan an identifier or keyword."""
        while self.peek().isalnum() or self.peek() == '_':
            self.advance()
        
        text = self.source[self.start:self.current]
        token_type = self.keywords.get(text, TokenType.IDENTIFIER)
        self.add_token(token_type)
    
    def number(self) -> None:
        """Scan a number literal."""
        while self.peek().isdigit():
            self.advance()
        
        # Look for a fractional part
        if self.peek() == '.' and self.peek_next().isdigit():
            # Consume the "."
            self.advance()
            
            while self.peek().isdigit():
                self.advance()
        
        value = float(self.source[self.start:self.current])
        self.add_token(TokenType.NUMBER, value)
    
    def string(self) -> None:
        """Scan a string literal."""
        while self.peek() != '"' and not self.is_at_end():
            if self.peek() == '\n':
                self.line += 1
            self.advance()
        
        if self.is_at_end():
            raise SyntaxError("Unterminated string")
        
        # The closing "
        self.advance()
        
        # Trim the surrounding quotes
        value = self.source[self.start + 1:self.current - 1]
        self.add_token(TokenType.STRING, value)
    
    def match(self, expected: str) -> bool:
        """Check if the current character matches the expected one."""
        if self.is_at_end():
            return False
        if self.source[self.current] != expected:
            return False
        
        self.current += 1
        return True
    
    def peek(self) -> str:
        """Look at the current character without consuming it."""
        if self.is_at_end():
            return '\0'
        return self.source[self.current]
    
    def peek_next(self) -> str:
        """Look at the next character without consuming it."""
        if self.current + 1 >= len(self.source):
            return '\0'
        return self.source[self.current + 1]
    
    def is_at_end(self) -> bool:
        """Check if we've reached the end of the source code."""
        return self.current >= len(self.source)
    
    def advance(self) -> str:
        """Consume and return the current character."""
        self.current += 1
        return self.source[self.current - 1]
    
    def add_token(self, token_type: TokenType, literal: Any = None) -> None:
        """Add a new token to the token list."""
        text = self.source[self.start:self.current]
        self.tokens.append(Token(token_type, text, literal, self.line))

class Parser:
    """Parses tokens into an abstract syntax tree (AST)."""
    
    def __init__(self, tokens: List[Token]):
        self.tokens = tokens
        self.current = 0
    
    def parse(self) -> List[ast.AST]:
        """Parse the tokens into an AST."""
        statements = []
        while not self.is_at_end():
            statements.append(self.declaration())
        return statements
    
    def declaration(self) -> ast.AST:
        """Parse a declaration (variable, function, or statement)."""
        try:
            if self.match(TokenType.CONTRACT):
                return self.contract_declaration()
            if self.match(TokenType.FUNCTION):
                return self.function_declaration()
            if self.match(TokenType.VAR, TokenType.CONST):
                return self.var_declaration()
            return self.statement()
        except ParseError:
            self.synchronize()
            return None
    
    def contract_declaration(self) -> ast.Contract:
        """Parse a contract declaration."""
        name = self.consume(TokenType.IDENTIFIER, "Expect contract name.")
        self.consume(TokenType.LEFT_BRACE, "Expect '{' before contract body.")
        
        methods = []
        while not self.check(TokenType.RIGHT_BRACE) and not self.is_at_end():
            methods.append(self.function_declaration())
        
        self.consume(TokenType.RIGHT_BRACE, "Expect '}' after contract body.")
        return ast.Contract(name, methods)
    
    def function_declaration(self) -> ast.Function:
        """Parse a function declaration."""
        name = self.consume(TokenType.IDENTIFIER, "Expect function name.")
        self.consume(TokenType.LEFT_PAREN, "Expect '(' after function name.")
        
        parameters = []
        if not self.check(TokenType.RIGHT_PAREN):
            parameters.append(self.consume(TokenType.IDENTIFIER, "Expect parameter name."))
            while self.match(TokenType.COMMA):
                parameters.append(self.consume(TokenType.IDENTIFIER, "Expect parameter name."))
        
        self.consume(TokenType.RIGHT_PAREN, "Expect ')' after parameters.")
        
        # Parse return type if present
        return_type = None
        if self.match(TokenType.COLON):
            return_type = self.type_annotation()
        
        self.consume(TokenType.LEFT_BRACE, "Expect '{' before function body.")
        body = self.block_statement()
        
        return ast.Function(name, parameters, return_type, body)
    
    def type_annotation(self) -> ast.Type:
        """Parse a type annotation."""
        if self.match(TokenType.UINT):
            size = 256  # Default size
            if self.match(TokenType.LEFT_BRACKET):
                size_token = self.consume(TokenType.NUMBER, "Expect bit size after '['.")
                size = int(size_token.literal)
                self.consume(TokenType.RIGHT_BRACKET, "Expect ']' after bit size.")
            return ast.IntegerType(size)
        elif self.match(TokenType.ADDRESS):
            return ast.AddressType()
        elif self.match(TokenType.BOOL):
            return ast.BooleanType()
        elif self.match(TokenType.STR):
            return ast.StringType()
        elif self.match(TokenType.BYTES):
            size = None
            if self.match(TokenType.LEFT_BRACKET):
                size_token = self.consume(TokenType.NUMBER, "Expect byte size after '['.")
                size = int(size_token.literal)
                self.consume(TokenType.RIGHT_BRACKET, "Expect ']' after byte size.")
            return ast.BytesType(size)
        elif self.match(TokenType.MAPPING):
            self.consume(TokenType.LESS, "Expect '<' after 'mapping'.")
            key_type = self.type_annotation()
            self.consume(TokenType.COMMA, "Expect ',' in mapping type.")
            value_type = self.type_annotation()
            self.consume(TokenType.GREATER, "Expect '>' to close mapping type.")
            return ast.MappingType(key_type, value_type)
        else:
            raise self.error(self.peek(), "Expect type.")
    
    def var_declaration(self) -> ast.Var:
        """Parse a variable declaration."""
        is_const = self.previous().type == TokenType.CONST
        name = self.consume(TokenType.IDENTIFIER, "Expect variable name.")
        
        type_annotation = None
        if self.match(TokenType.COLON):
            type_annotation = self.type_annotation()
        
        initializer = None
        if self.match(TokenType.EQUAL):
            initializer = self.expression()
        
        self.consume(TokenType.SEMICOLON, "Expect ';' after variable declaration.")
        return ast.Var(name, type_annotation, initializer, is_const)
    
    def statement(self) -> ast.Stmt:
        """Parse a statement."""
        if self.match(TokenType.IF):
            return self.if_statement()
        if self.match(TokenType.WHILE):
            return self.while_statement()
        if self.match(TokenType.FOR):
            return self.for_statement()
        if self.match(TokenType.RETURN):
            return self.return_statement()
        if self.match(TokenType.LEFT_BRACE):
            return ast.Block(self.block_statement())
        
        return self.expression_statement()
    
    def if_statement(self) -> ast.If:
        """Parse an if statement."""
        self.consume(TokenType.LEFT_PAREN, "Expect '(' after 'if'.")
        condition = self.expression()
        self.consume(TokenType.RIGHT_PAREN, "Expect ')' after if condition.")
        
        then_branch = self.statement()
        else_branch = None
        if self.match(TokenType.ELSE):
            else_branch = self.statement()
        
        return ast.If(condition, then_branch, else_branch)
    
    def while_statement(self) -> ast.While:
        """Parse a while loop."""
        self.consume(TokenType.LEFT_PAREN, "Expect '(' after 'while'.")
        condition = self.expression()
        self.consume(TokenType.RIGHT_PAREN, "Expect ')' after condition.")
        
        body = self.statement()
        return ast.While(condition, body)
    
    def for_statement(self) -> ast.Block:
        """Parse a for loop."""
        self.consume(TokenType.LEFT_PAREN, "Expect '(' after 'for'.")
        
        # Initializer
        initializer = None
        if self.match(TokenType.SEMICOLON):
            initializer = None
        elif self.match(TokenType.VAR, TokenType.CONST):
            initializer = self.var_declaration()
        else:
            initializer = self.expression_statement()
        
        # Condition
        condition = None
        if not self.check(TokenType.SEMICOLON):
            condition = self.expression()
        self.consume(TokenType.SEMICOLON, "Expect ';' after loop condition.")
        
        # Increment
        increment = None
        if not self.check(TokenType.RIGHT_PAREN):
            increment = self.expression()
        self.consume(TokenType.RIGHT_PAREN, "Expect ')' after for clauses.")
        
        # Body
        body = self.statement()
        
        # Desugar for loop into a while loop
        statements = []
        if initializer is not None:
            statements.append(initializer)
        
        if condition is None:
            condition = ast.Literal(True)
        
        while_loop = ast.While(condition, ast.Block([body, ast.Expression(increment)]) if increment is not None else body)
        statements.append(while_loop)
        
        return ast.Block(statements)
    
    def return_statement(self) -> ast.Return:
        """Parse a return statement."""
        keyword = self.previous()
        value = None
        if not self.check(TokenType.SEMICOLON):
            value = self.expression()
        
        self.consume(TokenType.SEMICOLON, "Expect ';' after return value.")
        return ast.Return(keyword, value)
    
    def block_statement(self) -> List[ast.Stmt]:
        """Parse a block of statements."""
        statements = []
        while not self.check(TokenType.RIGHT_BRACE) and not self.is_at_end():
            statements.append(self.declaration())
        
        self.consume(TokenType.RIGHT_BRACE, "Expect '}' after block.")
        return statements
    
    def expression_statement(self) -> ast.Expression:
        """Parse an expression statement."""
        expr = self.expression()
        self.consume(TokenType.SEMICOLON, "Expect ';' after expression.")
        return ast.Expression(expr)
    
    def expression(self) -> ast.Expr:
        """Parse an expression."""
        return self.assignment()
    
    def assignment(self) -> ast.Expr:
        """Parse an assignment expression."""
        expr = self.logical_or()
        
        if self.match(TokenType.EQUAL):
            equals = self.previous()
            value = self.assignment()
            
            if isinstance(expr, ast.Variable):
                name = expr.name
                return ast.Assign(name, value)
            
            self.error(equals, "Invalid assignment target.")
        
        return expr
    
    def logical_or(self) -> ast.Expr:
        """Parse a logical OR expression."""
        expr = self.logical_and()
        
        while self.match(TokenType.OR):
            operator = self.previous()
            right = self.logical_and()
            expr = ast.Logical(expr, operator, right)
        
        return expr
    
    def logical_and(self) -> ast.Expr:
        """Parse a logical AND expression."""
        expr = self.equality()
        
        while self.match(TokenType.AND):
            operator = self.previous()
            right = self.equality()
            expr = ast.Logical(expr, operator, right)
        
        return expr
    
    def equality(self) -> ast.Expr:
        """Parse an equality expression."""
        expr = self.comparison()
        
        while self.match(TokenType.BANG_EQUAL, TokenType.EQUAL_EQUAL):
            operator = self.previous()
            right = self.comparison()
            expr = ast.Binary(expr, operator, right)
        
        return expr
    
    def comparison(self) -> ast.Expr:
        """Parse a comparison expression."""
        expr = self.term()
        
        while self.match(TokenType.GREATER, TokenType.GREATER_EQUAL, 
                        TokenType.LESS, TokenType.LESS_EQUAL):
            operator = self.previous()
            right = self.term()
            expr = ast.Binary(expr, operator, right)
        
        return expr
    
    def term(self) -> ast.Expr:
        """Parse a term (addition/subtraction)."""
        expr = self.factor()
        
        while self.match(TokenType.MINUS, TokenType.PLUS):
            operator = self.previous()
            right = self.factor()
            expr = ast.Binary(expr, operator, right)
        
        return expr
    
    def factor(self) -> ast.Expr:
        """Parse a factor (multiplication/division/modulo)."""
        expr = self.unary()
        
        while self.match(TokenType.SLASH, TokenType.STAR, TokenType.MODULO):
            operator = self.previous()
            right = self.unary()
            expr = ast.Binary(expr, operator, right)
        
        return expr
    
    def unary(self) -> ast.Expr:
        """Parse a unary expression."""
        if self.match(TokenType.BANG, TokenType.MINUS):
            operator = self.previous()
            right = self.unary()
            return ast.Unary(operator, right)
        
        return self.call()
    
    def call(self) -> ast.Expr:
        """Parse a function call."""
        expr = self.primary()
        
        while True:
            if self.match(TokenType.LEFT_PAREN):
                expr = self.finish_call(expr)
            else:
                break
        
        return expr
    
    def finish_call(self, callee: ast.Expr) -> ast.Expr:
        """Finish parsing a function call."""
        arguments = []
        if not self.check(TokenType.RIGHT_PAREN):
            arguments.append(self.expression())
            while self.match(TokenType.COMMA):
                arguments.append(self.expression())
        
        paren = self.consume(TokenType.RIGHT_PAREN, "Expect ')' after arguments.")
        return ast.Call(callee, paren, arguments)
    
    def primary(self) -> ast.Expr:
        """Parse a primary expression."""
        if self.match(TokenType.FALSE):
            return ast.Literal(False)
        if self.match(TokenType.TRUE):
            return ast.Literal(True)
        if self.match(TokenType.NIL):
            return ast.Literal(None)
        
        if self.match(TokenType.NUMBER, TokenType.STRING):
            return ast.Literal(self.previous().literal)
        
        if self.match(TokenType.IDENTIFIER):
            return ast.Variable(self.previous())
        
        if self.match(TokenType.LEFT_PAREN):
            expr = self.expression()
            self.consume(TokenType.RIGHT_PAREN, "Expect ')' after expression.")
            return ast.Grouping(expr)
        
        raise self.error(self.peek(), "Expect expression.")
    
    def match(self, *types: TokenType) -> bool:
        """Check if the current token matches any of the given types."""
        for type_ in types:
            if self.check(type_):
                self.advance()
                return True
        return False
    
    def check(self, type_: TokenType) -> bool:
        """Check if the current token is of the given type."""
        if self.is_at_end():
            return False
        return self.peek().type == type_
    
    def advance(self) -> Token:
        """Consume and return the current token."""
        if not self.is_at_end():
            self.current += 1
        return self.previous()
    
    def is_at_end(self) -> bool:
        """Check if we've reached the end of the tokens."""
        return self.peek().type == TokenType.EOF
    
    def peek(self) -> Token:
        """Return the current token without consuming it."""
        return self.tokens[self.current]
    
    def previous(self) -> Token:
        """Return the most recently consumed token."""
        return self.tokens[self.current - 1]
    
    def consume(self, type_: TokenType, message: str) -> Token:
        """Consume a token of the expected type, or raise an error."""
        if self.check(type_):
            return self.advance()
        
        raise self.error(self.peek(), message)
    
    def error(self, token: Token, message: str) -> ParseError:
        """Create a parse error for the given token."""
        from . import ParseError
        return ParseError(token, message)
    
    def synchronize(self) -> None:
        """Recover from an error by synchronizing the parser."""
        self.advance()
        
        while not self.is_at_end():
            if self.previous().type == TokenType.SEMICOLON:
                return
            
            if self.peek().type in (
                TokenType.CLASS, TokenType.FUNCTION, TokenType.VAR, 
                TokenType.FOR, TokenType.IF, TokenType.WHILE,
                TokenType.PRINT, TokenType.RETURN
            ):
                return
            
            self.advance()

class Compiler:
    """Compiles Brixa Smart Contract Language (BSCL) to bytecode."""
    
    def __init__(self):
        self.bytecode = bytearray()
        self.constants = []
        self.labels = {}
        self.patch_list = []
    
    def compile(self, source: str) -> bytes:
        """Compile BSCL source code to bytecode."""
        # Lexical analysis
        scanner = Scanner(source)
        tokens = scanner.scan_tokens()
        
        # Parsing
        parser = Parser(tokens)
        statements = parser.parse()
        
        # Code generation
        for stmt in statements:
            self.visit(stmt)
        
        # Resolve labels
        self.patch_labels()
        
        # Prepend the constant pool
        constant_pool = self.encode_constant_pool()
        bytecode = len(constant_pool).to_bytes(4, 'big') + constant_pool + bytes(self.bytecode)
        
        return bytes(bytecode)
    
    def emit_byte(self, byte: int) -> None:
        """Emit a single byte of bytecode."""
        self.bytecode.append(byte)
    
    def emit_bytes(self, *bytes_: int) -> None:
        """Emit multiple bytes of bytecode."""
        self.bytecode.extend(bytes_)
    
    def emit_short(self, value: int) -> None:
        """Emit a 2-byte value in big-endian order."""
        self.bytecode.extend(value.to_bytes(2, 'big'))
    
    def emit_int(self, value: int) -> None:
        """Emit a 4-byte value in big-endian order."""
        self.bytecode.extend(value.to_bytes(4, 'big'))
    
    def emit_string(self, string: str) -> None:
        """Emit a string as a length-prefixed UTF-8 sequence."""
        encoded = string.encode('utf-8')
        self.emit_short(len(encoded))
        self.bytecode.extend(encoded)
    
    def make_label(self) -> int:
        """Create a new label and return its ID."""
        return len(self.labels)
    
    def mark_label(self, label: int) -> None:
        """Mark the current position with the given label."""
        self.labels[label] = len(self.bytecode)
    
    def emit_jump(self, opcode: int, label: int) -> None:
        """Emit a jump instruction to the given label."""
        self.emit_byte(opcode)
        self.patch_list.append((len(self.bytecode), label))
        self.emit_short(0)  # Placeholder for the jump offset
    
    def patch_labels(self) -> None:
        """Patch all jump instructions with the correct offsets."""
        for pos, label in self.patch_list:
            target = self.labels.get(label, 0)
            offset = target - pos - 2  # 2 bytes for the jump offset itself
            self.bytecode[pos:pos+2] = offset.to_bytes(2, 'big', signed=True)
    
    def encode_constant_pool(self) -> bytes:
        """Encode the constant pool as a binary blob."""
        # TODO: Implement constant pool encoding
        return b''
    
    def visit(self, node: ast.AST) -> None:
        """Dispatch to the appropriate visitor method."""
        method_name = 'visit_' + node.__class__.__name__
        method = getattr(self, method_name, self.generic_visit)
        method(node)
    
    def generic_visit(self, node: ast.AST) -> None:
        """Default visitor method for AST nodes."""
        raise NotImplementedError(f"No visit method for {node.__class__.__name__}")
    
    def visit_Contract(self, node: ast.Contract) -> None:
        """Visit a contract node."""
        for method in node.methods:
            self.visit(method)
    
    def visit_Function(self, node: ast.Function) -> None:
        """Visit a function node."""
        # Function prologue
        self.emit_byte(0x50)  # ENTER
        
        # Compile function body
        for stmt in node.body:
            self.visit(stmt)
        
        # If the function doesn't end with a return, add an implicit return
        if not isinstance(node.body[-1], ast.Return):
            self.emit_byte(0x60)  # RETURN
        
        # Function epilogue
        self.emit_byte(0x51)  # LEAVE
    
    def visit_Var(self, node: ast.Var) -> None:
        """Visit a variable declaration node."""
        if node.initializer is not None:
            self.visit(node.initializer)
        else:
            # Push default value based on type
            if isinstance(node.type_annotation, ast.IntegerType):
                self.emit_byte(0x60)  # PUSH1 0x00
                self.emit_byte(0x00)
            elif isinstance(node.type_annotation, ast.BooleanType):
                self.emit_byte(0x60)  # PUSH1 0x00
                self.emit_byte(0x00)
            elif isinstance(node.type_annotation, ast.AddressType):
                self.emit_byte(0x73)  # PUSH20 0x00...00
                self.emit_bytes(*[0] * 20)
            else:
                # Default to pushing 0
                self.emit_byte(0x60)  # PUSH1 0x00
                self.emit_byte(0x00)
        
        # Store the variable
        self.emit_byte(0x81)  # DUP2
        self.emit_byte(0x90)  # SWAP1
        self.emit_byte(0x55)  # SSTORE
    
    def visit_Assign(self, node: ast.Assign) -> None:
        """Visit an assignment node."""
        # Compile the right-hand side
        self.visit(node.value)
        
        # Store the value in the variable
        var_name = node.target.lexeme
        # TODO: Look up variable storage location
        self.emit_byte(0x81)  # DUP2
        self.emit_byte(0x90)  # SWAP1
        self.emit_byte(0x55)  # SSTORE
    
    def visit_If(self, node: ast.If) -> None:
        """Visit an if statement node."""
        # Compile the condition
        self.visit(node.condition)
        
        # Emit conditional jump
        else_label = self.make_label()
        end_label = self.make_label()
        
        self.emit_byte(0x15)  # ISZERO
        self.emit_jump(0x57, else_label)  # JUMPI
        
        # Compile the then branch
        self.visit(node.then_branch)
        
        if node.else_branch is not None:
            self.emit_jump(0x56, end_label)  # JUMP
        
        # Else branch
        self.mark_label(else_label)
        if node.else_branch is not None:
            self.visit(node.else_branch)
            self.mark_label(end_label)
    
    def visit_While(self, node: ast.While) -> None:
        """Visit a while loop node."""
        start_label = self.make_label()
        exit_label = self.make_label()
        
        # Mark the start of the loop
        self.mark_label(start_label)
        
        # Compile the condition
        self.visit(node.condition)
        
        # Jump to exit if condition is false
        self.emit_byte(0x15)  # ISZERO
        self.emit_jump(0x57, exit_label)  # JUMPI
        
        # Compile the loop body
        self.visit(node.body)
        
        # Jump back to the condition
        self.emit_jump(0x56, start_label)  # JUMP
        
        # Mark the exit point
        self.mark_label(exit_label)
    
    def visit_Block(self, node: ast.Block) -> None:
        """Visit a block node."""
        for stmt in node.statements:
            self.visit(stmt)
    
    def visit_Expression(self, node: ast.Expression) -> None:
        """Visit an expression statement node."""
        self.visit(node.expression)
        self.emit_byte(0x50)  # POP (discard the result)
    
    def visit_Return(self, node: ast.Return) -> None:
        """Visit a return statement node."""
        if node.value is not None:
            self.visit(node.value)
            self.emit_byte(0x60)  # RETURN
        else:
            self.emit_byte(0x60)  # RETURN (implicit None/void)
    
    def visit_Binary(self, node: ast.Binary) -> None:
        """Visit a binary expression node."""
        # Compile left and right operands
        self.visit(node.left)
        self.visit(node.right)
        
        # Emit the appropriate opcode
        if node.operator.type == TokenType.PLUS:
            self.emit_byte(0x01)  # ADD
        elif node.operator.type == TokenType.MINUS:
            self.emit_byte(0x03)  # SUB
        elif node.operator.type == TokenType.STAR:
            self.emit_byte(0x02)  # MUL
        elif node.operator.type == TokenType.SLASH:
            self.emit_byte(0x04)  # DIV
        elif node.operator.type == TokenType.MODULO:
            self.emit_byte(0x06)  # MOD
        elif node.operator.type == TokenType.EQUAL_EQUAL:
            self.emit_byte(0x14)  # EQ
        elif node.operator.type == TokenType.BANG_EQUAL:
            self.emit_byte(0x14)  # EQ
            self.emit_byte(0x15)  # ISZERO
        elif node.operator.type == TokenType.GREATER:
            self.emit_byte(0x11)  # GT
        elif node.operator.type == TokenType.GREATER_EQUAL:
            self.emit_byte(0x10)  # LT
            self.emit_byte(0x15)  # ISZERO
        elif node.operator.type == TokenType.LESS:
            self.emit_byte(0x10)  # LT
        elif node.operator.type == TokenType.LESS_EQUAL:
            self.emit_byte(0x11)  # GT
            self.emit_byte(0x15)  # ISZERO
        else:
            raise ValueError(f"Unsupported binary operator: {node.operator.type}")
    
    def visit_Unary(self, node: ast.Unary) -> None:
        """Visit a unary expression node."""
        # Compile the operand
        self.visit(node.right)
        
        # Emit the appropriate opcode
        if node.operator.type == TokenType.MINUS:
            self.emit_byte(0x60)  # PUSH1 0x00
            self.emit_byte(0x00)
            self.emit_byte(0x03)  # SUB
        elif node.operator.type == TokenType.BANG:
            self.emit_byte(0x15)  # ISZERO
        else:
            raise ValueError(f"Unsupported unary operator: {node.operator.type}")
    
    def visit_Literal(self, node: ast.Literal) -> None:
        """Visit a literal expression node."""
        if node.value is None:
            self.emit_byte(0x60)  # PUSH1 0x00
            self.emit_byte(0x00)
        elif isinstance(node.value, bool):
            self.emit_byte(0x60)  # PUSH1
            self.emit_byte(0x01 if node.value else 0x00)
        elif isinstance(node.value, int):
            # Push the integer value onto the stack
            if 0 <= node.value <= 0xff:
                self.emit_byte(0x60)  # PUSH1
                self.emit_byte(node.value)
            elif 0x100 <= node.value <= 0xffff:
                self.emit_byte(0x61)  # PUSH2
                self.emit_short(node.value)
            else:
                # For larger numbers, we'd need to handle them in chunks
                # This is a simplified version that only handles up to 32-bit integers
                self.emit_byte(0x62)  # PUSH3
                self.emit_byte((node.value >> 16) & 0xff)
                self.emit_short(node.value & 0xffff)
        elif isinstance(node.value, str):
            # Store the string in the constant pool
            const_index = len(self.constants)
            self.constants.append(node.value)
            
            # Push the length and offset of the string
            self.emit_byte(0x60)  # PUSH1
            self.emit_byte(const_index)  # Constant pool index
            self.emit_byte(0x60)  # PUSH1
            self.emit_byte(0x00)  # Offset (0 for now)
            self.emit_byte(0x60)  # PUSH1
            self.emit_byte(len(node.value))  # Length
        else:
            raise ValueError(f"Unsupported literal type: {type(node.value).__name__}")
    
    def visit_Variable(self, node: ast.Variable) -> None:
        """Visit a variable reference node."""
        # TODO: Look up variable storage location
        self.emit_byte(0x60)  # PUSH1 (variable storage slot)
        self.emit_byte(0x00)  # Placeholder for variable slot
        self.emit_byte(0x54)  # SLOAD
    
    def visit_Call(self, node: ast.Call) -> None:
        """Visit a function call node."""
        # Push arguments in reverse order
        for arg in reversed(node.arguments):
            self.visit(arg)
        
        # Push the function address
        self.visit(node.callee)
        
        # Emit CALL opcode
        # TODO: Handle different calling conventions
        self.emit_byte(0x5a)  # GAS
        self.emit_byte(0xf1)  # CALL
    
    def visit_Grouping(self, node: ast.Grouping) -> None:
        """Visit a grouping expression node."""
        self.visit(node.expression)

class Decompiler:
    """Decompiles Brixa bytecode back into BSCL source code."""
    
    def __init__(self, bytecode: bytes):
        self.bytecode = bytecode
        self.pos = 0
        self.output = []
        
        # Parse the constant pool
        self.constant_pool = self.parse_constant_pool()
    
    def parse_constant_pool(self) -> List[Any]:
        """Parse the constant pool from the bytecode."""
        if len(self.bytecode) < 4:
            return []
        
        # First 4 bytes are the length of the constant pool
        pool_size = int.from_bytes(self.bytecode[:4], 'big')
        self.pos = 4  # Skip the length
        
        constants = []
        while self.pos < 4 + pool_size:
            # Each constant is preceded by a type byte
            if self.pos >= len(self.bytecode):
                break
                
            const_type = self.bytecode[self.pos]
            self.pos += 1
            
            if const_type == 0x01:  # Integer
                value = int.from_bytes(self.bytecode[self.pos:self.pos+32], 'big', signed=True)
                self.pos += 32
                constants.append(value)
            elif const_type == 0x02:  # String
                length = int.from_bytes(self.bytecode[self.pos:self.pos+2], 'big')
                self.pos += 2
                value = self.bytecode[self.pos:self.pos+length].decode('utf-8')
                self.pos += length
                constants.append(value)
            elif const_type == 0x03:  # Boolean
                value = bool(self.bytecode[self.pos])
                self.pos += 1
                constants.append(value)
            elif const_type == 0x04:  # Address
                value = '0x' + self.bytecode[self.pos:self.pos+20].hex()
                self.pos += 20
                constants.append(value)
            else:
                raise ValueError(f"Unknown constant type: 0x{const_type:02x}")
        
        return constants
    
    def decompile(self) -> str:
        """Decompile the bytecode into BSCL source code."""
        # TODO: Implement actual decompilation
        return "// Decompiled Brixa Smart Contract\n// TODO: Implement decompiler"

class ParseError(Exception):
    """Raised when a parse error occurs."""
    def __init__(self, token: Token, message: str):
        self.token = token
        self.message = message
        super().__init__(f"{message} at line {token.line}")

# Example usage
if __name__ == "__main__":
    # Example BSCL source code
    source = """
    contract Counter {
        var count: uint = 0;
        
        function increment() public {
            count = count + 1;
        }
        
        function getCount() public returns (uint) {
            return count;
        }
    }
    """
    
    # Compile the source code
    compiler = Compiler()
    bytecode = compiler.compile(source)
    print(f"Compiled bytecode: {bytecode.hex()}")
    
    # Decompile the bytecode
    decompiler = Decompiler(bytecode)
    print("\nDecompiled source:")
    print(decompiler.decompile())
