{-# Language ApplicativeDo, FlexibleContexts, BangPatterns, ScopedTypeVariables #-}
import Control.Applicative
import Control.Monad
import Control.Monad.Trans.Class
import Data.Functor
import Data.Foldable
import Data.List
import Data.Maybe
import qualified Data.Map as M
import Data.Word
import Data.Int
import Data.Bits
import Data.Char (ord)
import qualified Data.ByteString.Lazy as BL
import qualified Control.Monad.State.Strict as SS
import Data.Binary.Put
import Text.Parsec hiding ((<|>), many, optional)
import qualified Text.Parsec.Token as P
import qualified Text.Parsec.Language as PL
import System.Environment
import System.Exit


-- MEMES --

-- From Relude.List
infix 9 !!?
(!!?) :: [a] -> Int -> Maybe a
(!!?) xs i
    | i < 0     = Nothing
    | otherwise = go i xs
  where
    go :: Int -> [a] -> Maybe a
    go 0 (x:_)  = Just x
    go j (_:ys) = go (j - 1) ys
    go _ []     = Nothing
{-# INLINE (!!?) #-}

class Serializable t where
    put :: t -> Put

padBytes :: Int -> Put
padBytes n = sequence_ $ replicate n $ putWord8 0

-- Adapted from https://stackoverflow.com/a/17970063
runSubparser
    :: forall m s u v a . (Monad m)
    => ParsecT s u m a -> u -> ParsecT s v m a
runSubparser innerP initSt = mkPT outerPR
  where
    fmap3 f = fmap $ fmap $ fmap f

    setState :: forall u v . v -> State s u -> State s v
    setState v st = st { stateUser = v }

    setReplyState :: forall u v . v -> Reply s u a -> Reply s v a
    setReplyState v (Ok a st err) = Ok a (setState v st) err
    setReplyState _ (Error e) = Error e

    innerPR = runParsecT innerP

    outerPR :: State s v -> m (Consumed (m (Reply s v a)))
    outerPR st = fmap3 (setReplyState (stateUser st)) $ innerPR $ setState initSt st

narrowSafe :: forall a b . (Integral a, Bounded a, Integral b, Bounded b) => a -> Maybe b
narrowSafe v =
    if (toInteger v < toInteger (minBound :: b) ||
        toInteger v > toInteger (maxBound :: b))
        then Nothing
        else Just $ fromIntegral v

narrowSafeBothSign :: forall a b . (Integral a, Bits a, Integral b, FiniteBits b) => a -> Maybe b
narrowSafeBothSign v = if v < (shiftL 1 bits) && v >= -(shiftL 1 (bits - 1))
    then Just $ fromIntegral v
    else Nothing
  where
    bits = finiteBitSize (0 :: b)


-- PARSING --

langDef :: P.LanguageDef st
langDef = PL.javaStyle
          { P.caseSensitive = True
          }

P.TokenParser { P.parens = m_parens
              , P.braces = m_braces
              , P.reserved = m_reserved
              , P.identifier = m_ident
              , P.symbol = m_symbol
              , P.natural = m_natural
              , P.integer = m_integer
              , P.charLiteral = m_charLiteral
              , P.stringLiteral = m_stringLiteral
              , P.dot = m_dot
              , P.colon = m_colon
              , P.semi = m_semi
              , P.commaSep = m_commaSep
              , P.lexeme = m_lexeme
              , P.whiteSpace = m_whiteSpace
              } = P.makeTokenParser langDef


m_naturali :: (Integral a) => Parsec String u a
m_naturali = fromInteger <$> m_natural

m_naturalb :: forall a u . (Integral a, Bounded a) => Parsec String u a
m_naturalb = do
    l <- m_natural
    -- TODO: use narrowSafe somehow
    when (l < toInteger (minBound :: a) ||
          l > toInteger (maxBound :: a)) $
        fail "number out of bounds"
    pure $ fromInteger l


m_compound :: String -> Parsec String u ()
m_compound s = unwrap $ try <$> parse compound_builder "" s
  where
    unwrap :: Either ParseError a -> a
    unwrap (Left err) = error $ show err
    unwrap (Right a) = a
    compound_builder :: Parsec String u (Parsec String v ())
    compound_builder = sequenceA_ . intersperse (void m_dot) . map m_reserved <$> m_ident `sepBy1` m_dot


p_alias_ref :: (Bounded n, Integral n) => Parsec String u (AliasRef n)
p_alias_ref = choice
    [ m_naturalb <&> RefIdx
    , m_ident    <&> RefName
    ] <?> "numeric index or symbolic name"

p_zary_op :: Parsec String u ZAryOp
p_zary_op = choice
    [ m_compound "nop" $> OpNop
    , m_compound "drop" $> OpDrop
    , m_compound "dup" $> OpDup
    , m_compound "ret" $> OpRet
    , m_compound "mem.lw"  $> OpMemLw
    , m_compound "mem.lh"  $> OpMemLh
    , m_compound "mem.lb"  $> OpMemLb
    , m_compound "mem.lhu" $> OpMemLhu
    , m_compound "mem.lbu" $> OpMemLbu
    , m_compound "mem.sw"  $> OpMemSw
    , m_compound "mem.sh"  $> OpMemSh
    , m_compound "mem.sb"  $> OpMemSb
    , m_compound "const.lw"  $> OpConstLw
    , m_compound "const.lh"  $> OpConstLh
    , m_compound "const.lb"  $> OpConstLb
    , m_compound "const.lhu" $> OpConstLhu
    , m_compound "const.lbu" $> OpConstLbu
    , m_compound "eqz" $> OpEqz
    , m_compound "nez" $> OpNez
    , m_compound "eq"  $> OpEq
    , m_compound "ne"  $> OpNe
    , m_compound "lt"  $> OpLt
    , m_compound "gt"  $> OpGt
    , m_compound "le"  $> OpLe
    , m_compound "ge"  $> OpGe
    , m_compound "ltu" $> OpLtu
    , m_compound "gtu" $> OpGtu
    , m_compound "leu" $> OpLeu
    , m_compound "geu" $> OpGeu
    , m_compound "and" $> OpAnd
    , m_compound "or"  $> OpOr
    , m_compound "xor" $> OpXor
    , m_compound "add" $> OpAdd
    , m_compound "sub" $> OpSub
    , m_compound "shl" $> OpShl
    , m_compound "shr" $> OpShr
    , m_compound "sar" $> OpSar
    ]

p_br_op :: Parsec String u BrOp
p_br_op = choice
    [ m_compound "br" $> OpBr
    , m_compound "br_if" $> OpBrIf
    ]

p_local_op :: Parsec String u LocalOp
p_local_op = choice
    [ m_compound "local.get" $> OpLocalGet
    , m_compound "local.set" $> OpLocalSet
    , m_compound "local.tee" $> OpLocalTee
    ]

p_label :: Parsec String u String
p_label = try (m_ident <* m_colon) <?> "named label"

p_imm_op :: Parsec String u AsmImmWidth
p_imm_op = choice
    [ m_compound "li.w" $> AIWFixed ImmW
    , m_compound "li.h" $> AIWFixed ImmH
    , m_compound "li.b" $> AIWFixed ImmB
    , m_compound "li"   $> AIWAuto
    ]

p_imm_value :: Parsec String u ImmValue
p_imm_value = choice
    [ ImmLiteral . fromInteger <$> m_integer
    , ImmRef <$> m_ident
    ]

p_instruction :: Parsec String u Instruction
p_instruction = choice
    [ p_zary_op <&> IZAry
    , liftA2 ILocal p_local_op (m_naturalb <?> "local identifier")
    , m_compound "arg.get" *> (IArgGet <$> m_naturalb <?> "argument identifier")
    , m_compound "call" *> (ICall <$> p_alias_ref)
    , liftA2 IBr p_br_op p_alias_ref
    , liftA2 IImm p_imm_op p_imm_value
    , m_reserved "#label:" $> ILabel Nothing
    , p_label <&> ILabel . Just
    ]

data FuncAttrParseEnum = FuncAttrPEPArgs | FuncAttrPEPRet | FuncAttrPEPLocals
    deriving (Show, Eq)

p_function_attr :: Parsec String [FuncAttrParseEnum] (FuncAttrParseEnum, Word8)
p_function_attr = do
    pending <- getState
    choice $ map parseAttr $ pending
  where
    parseAttr :: FuncAttrParseEnum -> Parsec String [FuncAttrParseEnum] (FuncAttrParseEnum, Word8)
    parseAttr a =
        m_reserved (enumToSymbol a) *> m_colon *> m_naturalb
        <* updateState (filter (/= a))
        <&> (,) a

    enumToSymbol :: FuncAttrParseEnum -> String
    enumToSymbol FuncAttrPEPArgs   = "args"
    enumToSymbol FuncAttrPEPRet    = "ret"
    enumToSymbol FuncAttrPEPLocals = "locals"

p_function_attrs :: Parsec String u FuncDef
p_function_attrs = do
    list <- runSubparser (m_commaSep p_function_attr) allTypes
    pure FuncDef
         { funcNArgs = fromMaybe 0 $ lookup FuncAttrPEPArgs list
         , funcNRet = fromMaybe 0 $ lookup FuncAttrPEPRet list
         , funcNLocals = fromMaybe 0 $ lookup FuncAttrPEPLocals list
         , funcName = Nothing
         , funcBody = []
         }
  where
    allTypes = [FuncAttrPEPArgs, FuncAttrPEPRet, FuncAttrPEPLocals]

p_function :: Parsec String u FuncDef
p_function = do
    m_reserved "function"
    name <- optional m_ident
    attrs <- m_parens p_function_attrs
    insns <- m_braces $ many (p_instruction <* optional m_semi)
    pure attrs
         { funcName = name
         , funcBody = insns
         }

p_initialized_section :: Parsec String u [InitMemEntry]
p_initialized_section = join <$> many (single <* optional m_semi)
  where
    ensure :: (a -> Bool) -> String -> a -> Parsec s u a
    ensure cond msg x = if cond x then pure x else fail msg

    literalOne :: (Int -> Bool) -> String -> Parsec String u Int
    literalOne cond name = choice
        [ check . fromInteger =<< m_integer
        , check . fromEnum =<< m_charLiteral
        ]
      where
        check = ensure cond ("value out of range for " ++ name)

    literal :: (Int -> Bool) -> String -> Parsec String u [Int]
    literal cond name = choice
        [ (:[]) <$> literalOne cond name
        , traverse (check . fromEnum) =<< m_stringLiteral
        ]
      where
        check = ensure cond ("value out of range for " ++ name)

    types :: [(String, String, Int -> InitMemEntryData, Int)]
    types = [ ("byte", "b", MEDB . fromIntegral, 8)
            , ("half", "h", MEDH . fromIntegral, 16)
            , ("word", "w", MEDW . fromIntegral, 32)
            ]

    checkRange :: Int -> (Int -> Bool)
    checkRange bits = \v -> v < (shiftL 1 bits) && v >= -(shiftL 1 (bits - 1))

    eData :: Parsec String u [InitMemEntryData]
    eData = choice $ mapper =<< types
      where
        mapper :: (String, String, Int -> InitMemEntryData, Int) -> [Parsec String u [InitMemEntryData]]
        mapper (name, mn, ctor, bits) =
            [ m_compound ("d" ++ mn) *> vals <&> map ctor . join
            , m_compound ("d" ++ mn ++ "z") *> vals <&> map ctor . (++ [0]) . join
            ]
          where
            vals = m_commaSep (literal check name)
            check = checkRange bits

    eDataOne :: Parsec String u InitMemEntryData
    eDataOne = choice $ map mapper types
      where
        mapper :: (String, String, Int -> InitMemEntryData, Int) -> Parsec String u InitMemEntryData
        mapper (name, mn, ctor, bits) =
            m_compound ("d" ++ mn) *> literalOne check name <&> ctor
              where
                check = checkRange bits

    eAlign :: Parsec String u InitMemEntry
    eAlign = do
        m_compound "align"
        align <- m_naturalb
        fill <- eDataOne
        pure $ MEAlign align fill

    single :: Parsec String u [InitMemEntry]
    single = choice
        [ eData <&> map MEData
        , eAlign <&> (:[])
        , p_label <&> (:[]) . MELabel
        ]

p_bss_section :: Parsec String u [BssEntry]
p_bss_section = many (single <* optional m_semi)
  where
    types :: [(String, String, Int -> BssEntry)]
    types = [ ("byte", "b", BEResB)
            , ("half", "h", BEResH)
            , ("word", "w", BEResW)
            ]

    eRes :: Parsec String u BssEntry
    eRes = choice $ map mapper types
      where
        mapper :: (String, String, Int -> BssEntry) -> Parsec String u BssEntry
        mapper (_, mn, ctor) = m_compound ("res" ++ mn) *> m_naturalb <&> ctor

    eAlign :: Parsec String u BssEntry
    eAlign = do
        m_compound "align"
        align <- m_naturalb
        pure $ BEAlign align

    single :: Parsec String u BssEntry
    single = choice
        [ eRes
        , eAlign
        , p_label <&> BELabel
        ]

data ModuleElemParseEnum = ModuleElemPEFunction FuncDef
                         | ModuleElemPEData [InitMemEntry]
                         | ModuleElemPERodata [InitMemEntry]
                         | ModuleElemPEBss [BssEntry]
    deriving (Show, Eq)

p_module_elem :: Parsec String u ModuleElemParseEnum
p_module_elem = choice
    [ p_function <&> ModuleElemPEFunction
    , section "data" p_initialized_section <&> ModuleElemPEData
    , section "rodata" p_initialized_section <&> ModuleElemPERodata
    , section "bss" p_bss_section <&> ModuleElemPEBss
    ]
  where
    section :: String -> Parsec String u a -> Parsec String u a
    section name p = m_reserved name *> m_braces p

p_module :: Parsec String u ModuleDef
p_module = do
    elems <- many p_module_elem
    pure ModuleDef
         { moduleFunctions = mapMaybe ( \x -> case x of
                ModuleElemPEFunction f -> Just f
                _ -> Nothing
            ) $ elems
         , moduleData = join $ mapMaybe ( \x -> case x of
                ModuleElemPEData d -> Just d
                _ -> Nothing
            ) $ elems
         , moduleRodata = join $ mapMaybe ( \x -> case x of
                ModuleElemPERodata d -> Just d
                _ -> Nothing
            ) $ elems
         , moduleBss = join $ mapMaybe ( \x -> case x of
                ModuleElemPEBss d -> Just d
                _ -> Nothing
            ) $ elems
         }


-- AST --

data ZAryOp = OpNop | OpDrop | OpDup | OpRet
            -- memory
            | OpMemLw | OpMemLh | OpMemLb
            | OpMemLhu | OpMemLbu
            | OpMemSw | OpMemSh | OpMemSb
            -- const
            | OpConstLw | OpConstLh | OpConstLb
            | OpConstLhu | OpConstLbu
            -- test
            | OpEqz | OpNez | OpEq | OpNe
            | OpLt | OpGt | OpLe | OpGe
            | OpLtu | OpGtu | OpLeu | OpGeu
            -- arith
            | OpAnd | OpOr | OpXor
            | OpAdd | OpSub
            | OpShl | OpShr | OpSar
    deriving (Show, Eq)

data BrOp = OpBr | OpBrIf
    deriving (Show, Eq)

data LocalOp = OpLocalGet | OpLocalSet | OpLocalTee
    deriving (Show, Eq)

data ImmWidth = ImmW | ImmH | ImmB
    deriving (Show, Eq)

data AsmImmWidth = AIWFixed ImmWidth | AIWAuto
    deriving (Show, Eq)

data ImmValue = ImmLiteral Int | ImmRef String
    deriving (Show, Eq)

data AliasRef n = RefName String | RefIdx n
    deriving (Show, Eq)

data Instruction = ILabel (Maybe String)
                 | IZAry ZAryOp
                 | ILocal LocalOp Word8
                 | IArgGet Word8
                 | ICall (AliasRef Word16)
                 | IBr BrOp (AliasRef Word16)
                 | IImm AsmImmWidth ImmValue
    deriving (Show, Eq)

data FuncDef = FuncDef
               { funcName :: Maybe String
               , funcNArgs :: Word8
               , funcNRet :: Word8
               , funcNLocals :: Word8
               , funcBody :: [Instruction]
               }
    deriving (Show, Eq)

data InitMemEntryData = MEDB Word8 | MEDH Word16 | MEDW Word32
    deriving (Show, Eq)

data InitMemEntry = MEData InitMemEntryData
                  | MEAlign Int InitMemEntryData
                  | MELabel String
    deriving (Show, Eq)

data BssEntry = BEResB Int | BEResH Int | BEResW Int
              | BEAlign Int
              | BELabel String
    deriving (Show, Eq)

data ModuleDef = ModuleDef
                 { moduleData :: [InitMemEntry]
                 , moduleRodata :: [InitMemEntry]
                 , moduleBss :: [BssEntry]
                 , moduleFunctions :: [FuncDef]
                 }
    deriving (Show, Eq)


-- ASSEMBLY --

alignUpDiff :: (Integral a) => a -> a -> a
alignUpDiff alignment = (`rem` alignment) . (alignment -) . (`rem` alignment)

alignUp :: (Integral a) => a -> a -> a
alignUp alignment = alignUpDiff alignment >>= (+)

splitBytesLe :: (FiniteBits a, Integral a) => a -> [Word8]
splitBytesLe n = map (fromIntegral . (n `shiftR`) . (*8)) [0..(finiteBitSize n `shiftR` 3) - 1]
splitBytesBe :: (FiniteBits a, Integral a) => a -> [Word8]
splitBytesBe = reverse . splitBytesLe

type SeekPutM = SS.StateT Int PutM
type SeekPut = SeekPutM ()

runSeekPutM :: Int -> SeekPutM a -> (a, Int, BL.ByteString)
runSeekPutM = ((flat . runPutM) .) . flip SS.runStateT
  where
    flat ((a, b), c) = (a, b, c)
runSeekPut :: Int -> SeekPut -> (Int, BL.ByteString)
runSeekPut = (drop1 .) . runSeekPutM
  where
    drop1 (_, a, b) = (a, b)
sTell :: SeekPutM Int
sTell = SS.get
sPutWord8 :: Word8 -> SeekPut
sPutWord8 v = do { lift $ putWord8 v; SS.modify (+ 1) }
sPutWord16le :: Word16 -> SeekPut
sPutWord16le v = do { lift $ putWord16le v; SS.modify (+ 2) }
sPutWord32le :: Word32 -> SeekPut
sPutWord32le v = do { lift $ putWord32le v; SS.modify (+ 4) }


assembleBss :: [BssEntry] -> SS.State Int (M.Map String Int)
assembleBss es = SS.execStateT m M.empty
  where
    m :: SS.StateT (M.Map String Int) (SS.State Int) ()
    m = traverse_ single es

    single :: BssEntry -> SS.StateT (M.Map String Int) (SS.State Int) ()
    single (BELabel s) = do
        m <- SS.get
        when (M.member s m) $ error "duplicate label"
        i <- lift SS.get
        SS.modify (M.insert s i)
    single (BEResB n) = lift $ SS.modify (+ n)
    single (BEResH n) = lift $ SS.modify (+ (n * 2))
    single (BEResW n) = lift $ SS.modify (+ (n * 4))
    single (BEAlign n) = lift $ SS.modify (alignUp n)

assembleInitMem :: [InitMemEntry] -> SeekPutM (M.Map String Int)
assembleInitMem es = SS.execStateT m M.empty
  where
    m :: SS.StateT (M.Map String Int) SeekPutM ()
    m = traverse_ single es

    single :: InitMemEntry -> SS.StateT (M.Map String Int) SeekPutM ()
    single (MELabel s) = do
        m <- SS.get
        when (M.member s m) $ error "duplicate label"
        pos <- lift sTell
        SS.modify (M.insert s pos)
    single (MEData d) = lift $ case d of
        MEDB v -> sPutWord8 v
        MEDH v -> sPutWord16le v
        MEDW v -> sPutWord32le v
    single (MEAlign n d) = do
        i <- lift sTell
        let delta = alignUpDiff n i
            go :: (FiniteBits a, Integral a) => a -> SeekPut
            go = traverse_ sPutWord8 . take delta . cycle . splitBytesLe
        lift $ case d of
            MEDB v -> go v
            MEDH v -> go v
            MEDW v -> go v

assembleFuncBody :: (M.Map String Int, M.Map String Int) -> [Instruction] -> BL.ByteString
assembleFuncBody (funcMap, dataLabelMap) es = runPut m
  where
    m :: Put
    m = traverse_ single es

    labels :: M.Map String Int
    !labels = SS.evalState m 0
      where
        m :: SS.State Int (M.Map String Int)
        m = SS.execStateT (traverse single es) M.empty

        single :: Instruction -> SS.StateT (M.Map String Int) (SS.State Int) ()
        single (ILabel l) = do
            i <- lift SS.get
            lift $ SS.modify (+1)
            case l of
                Just s  -> do
                    m <- SS.get
                    when (M.member s m) $ error "duplicate label"
                    SS.modify $ M.insert s i
                Nothing -> pure ()
        single _ = pure ()

    resolveImm :: ImmValue -> Int
    resolveImm (ImmLiteral v) = v
    resolveImm (ImmRef s) = dataLabelMap M.! s

    single :: Instruction -> Put
    single (IZAry op) = putWord8 $ case op of
        OpNop  -> 0x00
        OpDrop -> 0x01
        OpDup  -> 0x02
        OpRet  -> 0x11

        OpMemLw    -> 0x30
        OpMemLh    -> 0x31
        OpMemLb    -> 0x32
        OpMemLhu   -> 0x33
        OpMemLbu   -> 0x34
        OpMemSw    -> 0x35
        OpMemSh    -> 0x36
        OpMemSb    -> 0x37
        OpConstLw  -> 0x38
        OpConstLh  -> 0x39
        OpConstLb  -> 0x3a
        OpConstLhu -> 0x3b
        OpConstLbu -> 0x3c

        OpEqz -> 0x40
        OpNez -> 0x41
        OpEq  -> 0x42
        OpNe  -> 0x43
        OpLt  -> 0x44
        OpGt  -> 0x45
        OpLe  -> 0x46
        OpGe  -> 0x47
        OpLtu -> 0x48
        OpGtu -> 0x49
        OpLeu -> 0x4a
        OpGeu -> 0x4b

        OpAnd -> 0x50
        OpOr  -> 0x51
        OpXor -> 0x52
        OpAdd -> 0x53
        OpSub -> 0x54
        OpShl -> 0x5c
        OpShr -> 0x5d
        OpSar -> 0x5e

    single (IImm AIWAuto value) = single $ IImm (AIWFixed width) (ImmLiteral resolved)
      where
        resolved = resolveImm value

        width :: ImmWidth
        width = head $ catMaybes
            [ (narrowSafe resolved :: Maybe Int8 ) $> ImmB
            , (narrowSafe resolved :: Maybe Int16) $> ImmH
            , Just ImmW
            ]
    single (IImm (AIWFixed width) value) = case width of
        ImmW -> putWord8 0x08 *> (putWord32le $ fromIntegral resolvedValue)
        ImmH -> putWord8 0x09 *> (putWord16le $ fromIntegral resolvedValue)
        ImmB -> putWord8 0x0a *> (putWord8    $ fromIntegral resolvedValue)
      where
        resolvedValue = resolveImm value

    single (ILabel _) = putWord8 0x12
    single (ILocal op n) = do
        putWord8 $ case op of
            OpLocalGet -> 0x20
            OpLocalSet -> 0x21
            OpLocalTee -> 0x22
        putWord8 n
    single (IArgGet n) = putWord8 0x23 *> putWord8 n

    single (ICall r) = putWord8 0x10 *> putWord16le resolved
      where
        resolved = case r of
            RefIdx n -> n
            RefName s -> fromIntegral $ funcMap M.! s
    single (IBr op ref) = putWord8 bOp *> putWord16le resolved
      where
        resolved = case ref of
            RefIdx n -> n
            RefName s -> fromIntegral $ labels M.! s
        bOp :: Word8
        bOp = case op of
            OpBr   -> 0x13
            OpBrIf -> 0x14

data FuncTableEntry = FuncTableEntry
                      { fteOffset :: Word32
                      , fteLen :: Word32
                      , fteNArgs :: Word8
                      , fteNRet :: Word8
                      , fteNLocals :: Word8
                      }
    deriving (Show, Eq)

instance Serializable FuncTableEntry where
    put e = traverse_ ($ e)
        [ putWord32le . fteOffset
        , putWord32le . fteLen
        , putWord8 . fteNArgs
        , putWord8 . fteNRet
        , putWord8 . fteNLocals
        ] *>
        padBytes 1

data SegmentHeader = SegmentHeader
                     { shOffset :: Word32
                     , shFileSz :: Word32
                     , shMemSz  :: Word32
                     }
    deriving (Show, Eq)

instance Serializable SegmentHeader where
    put e = traverse_ ($ e)
        [ putWord32le . shOffset
        , putWord32le . shFileSz
        , putWord32le . shMemSz
        ]

data BytecodeHeader = BytecodeHeader
                      { bchShRodata :: SegmentHeader
                      , bchShData   :: SegmentHeader
                      , bchFuncTblSz :: Word16
                      }
    deriving (Show, Eq)

instance Serializable BytecodeHeader where
    put h = do
        traverse_ (putWord8 . fromIntegral . ord) "\x7frp2sm\r\0" -- magic
        traverse_ ($ h)
            [ put . bchShRodata
            , put . bchShData
            , putWord16le . bchFuncTblSz
            ] *> padBytes 2

assembleModule :: ModuleDef -> BL.ByteString
assembleModule ModuleDef
               { moduleData = secData
               , moduleRodata = secRodata
               , moduleBss = secBss
               , moduleFunctions = functions
               } = runPut topLevel
  where
    labelMerger :: (Ord k) => M.Map k v -> M.Map k v -> M.Map k v
    labelMerger = M.unionWith (error "duplicate labels")

    (dataLabels, dataLen, dataContents) = runSeekPutM 0 $ assembleInitMem secData
    (bssLabels, dataSecLen) = flip SS.runState dataLen $ assembleBss secBss
    (rodataLabels, rodataLen, rodataContents) = runSeekPutM 0 $ assembleInitMem secRodata

    allLabels = foldl1' labelMerger [dataLabels, bssLabels, rodataLabels]

    funcMap :: M.Map String Int
    funcMap = M.fromList $ mapMaybe mapper $ zip functions [0..]
      where
        mapper :: (FuncDef, Int) -> Maybe (String, Int)
        mapper (FuncDef { funcName = name }, i) =
            flip (,) i <$> name

    functionsContents :: [BL.ByteString]
    functionsContents = map (assembleFuncBody (funcMap, allLabels)) $ map funcBody functions

    funcTableSz = 0xc * length functions
    fullHeaderSz = 0x24 + funcTableSz
    rodataAddr = fullHeaderSz
    dataAddr = rodataAddr + rodataLen
    functionsStart = dataAddr + dataLen

    funcLens :: [Int64]
    funcLens = map (BL.length) functionsContents
    funcAddrs :: [Int]
    funcAddrs = scanl go functionsStart funcLens
      where
        go i l = i + (fromIntegral $ l)

    fullHeader :: Put
    fullHeader = do
        put BytecodeHeader
            { bchShRodata = SegmentHeader
                            { shOffset = fromIntegral rodataAddr
                            , shFileSz = fromIntegral rodataLen
                            , shMemSz  = fromIntegral rodataLen
                            }
            , bchShData = SegmentHeader
                          { shOffset = fromIntegral dataAddr
                          , shFileSz = fromIntegral dataLen
                          , shMemSz  = fromIntegral dataSecLen
                          }
            , bchFuncTblSz = fromIntegral $ length functions
            }
        traverse_ (put . makeEntry) $ zip functions (zip funcAddrs funcLens)
          where
            makeEntry :: (FuncDef, (Int, Int64)) -> FuncTableEntry
            makeEntry (def, (offs, len)) =
                FuncTableEntry
                { fteOffset = fromIntegral offs
                , fteLen = fromIntegral len
                , fteNArgs = fromIntegral $ funcNArgs def
                , fteNRet = fromIntegral $ funcNRet def
                , fteNLocals = fromIntegral $ funcNLocals def
                }

    topLevel :: Put
    topLevel = do
        fullHeader
        putLazyByteString rodataContents
        putLazyByteString dataContents
        traverse_ putLazyByteString functionsContents


-- MAIN --

main :: IO ()
main = do
    filename <- (!! 0) <$> getArgs
    outNameMay <- (!!? 1) <$> getArgs
    outName <- flip (liftM2 fromMaybe) (pure outNameMay) $ if ".rp2t" `isSuffixOf` filename
        then pure $ (init filename) ++ "b"
        else die "unknown extension and no output name given"
    source <- readFile filename
    case parse (m_whiteSpace *> p_module <* eof) filename source of
        Left err -> do
            die $ show err
        Right mod -> do
            let code = assembleModule mod
            BL.writeFile outName code
