using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Text.Json;

namespace DummyGen;

public sealed class FieldRec
{
    public string Name = "";
    public string Type = "obj";
    public uint Flags;
    public uint Token;
    public long? Offset;
}

public sealed class ParamRec
{
    public string Name = "";
    public string Type = "obj";
}

public sealed class MethodRec
{
    public string Name = "";
    public string Ret = "v";
    public uint Flags;
    public uint Rva;
    public uint Token;
    public int? Slot;
    public long? FileOffset;
    public List<ParamRec> Params = new();
}

public sealed class PropRec
{
    public string Name = "";
    public int Row;
    public int Get = -1;
    public int Set = -1;
}

public sealed class AttrRec
{
    public uint Token;
    public int Tdi;
    public string Name = "";
    public int Ctor = -1;
}

public sealed class EventRec
{
    public string Name = "";
    public int Row;
    public string Type = "obj";
    public int Add = -1;
    public int Remove = -1;
    public int Raise = -1;
}

public sealed class TypeRec
{
    public int Id;
    public string Ns = "";
    public string Name = "";
    public string Kind = "class";
    public int Parent = -1;
    public uint Flags;
    public List<FieldRec> Fields = new();
    public List<MethodRec> Methods = new();
    public List<PropRec> Props = new();
    public List<EventRec> Events = new();
    public List<int> Ifaces = new();
}

public static class Program
{
    public static int Main(string[] args)
    {
        if (args.Length < 2)
        {
            Console.Error.WriteLine("usage: dummygen <input.jsonl> <output.dll> [--verify-only]");
            return 2;
        }
        string input = args[0];
        string output = args[1];
        var types = Load(input, out var attrs);
        Console.WriteLine($"loaded {types.Count} types, {types.Sum(t => t.Fields.Count)} fields, {types.Sum(t => t.Methods.Count)} methods, {types.Sum(t => t.Props.Count)} properties, {types.Sum(t => t.Events.Count)} events, {attrs.Count} attribute instances");
        int emittedAttrs = Emit(types, attrs, output);
        Verify(output, types, attrs, emittedAttrs);
        return 0;
    }

    static List<TypeRec> Load(string path, out List<AttrRec> attrs)
    {
        var types = new List<TypeRec>();
        attrs = new List<AttrRec>();
        TypeRec? cur = null;
        using var reader = new StreamReader(path);
        string? line;
        while ((line = reader.ReadLine()) != null)
        {
            if (line.Length == 0) continue;
            using var doc = JsonDocument.Parse(line);
            var r = doc.RootElement;
            string k = r.GetProperty("k").GetString() ?? "";
            switch (k)
            {
                case "T":
                    cur = new TypeRec
                    {
                        Id = r.GetProperty("id").GetInt32(),
                        Ns = r.GetProperty("ns").GetString() ?? "",
                        Name = r.GetProperty("name").GetString() ?? "",
                        Kind = r.GetProperty("kind").GetString() ?? "class",
                        Parent = r.GetProperty("parent").GetInt32(),
                        Flags = r.GetProperty("flags").GetUInt32(),
                    };
                    types.Add(cur);
                    break;
                case "F":
                    var fr = new FieldRec
                    {
                        Name = r.GetProperty("name").GetString() ?? "",
                        Type = r.GetProperty("type").GetString() ?? "obj",
                        Flags = r.GetProperty("flags").GetUInt32(),
                    };
                    if (r.TryGetProperty("token", out var ftok)) fr.Token = ftok.GetUInt32();
                    if (r.TryGetProperty("off", out var foff) && foff.ValueKind == JsonValueKind.Number)
                        fr.Offset = foff.GetInt64();
                    cur!.Fields.Add(fr);
                    break;
                case "M":
                    var m = new MethodRec
                    {
                        Name = r.GetProperty("name").GetString() ?? "",
                        Ret = r.GetProperty("ret").GetString() ?? "v",
                        Flags = r.GetProperty("flags").GetUInt32(),
                    };
                    if (r.TryGetProperty("rva", out var mrva)) m.Rva = mrva.GetUInt32();
                    if (r.TryGetProperty("token", out var mtok)) m.Token = mtok.GetUInt32();
                    if (r.TryGetProperty("slot", out var mslot) && mslot.ValueKind == JsonValueKind.Number)
                        m.Slot = mslot.GetInt32();
                    if (r.TryGetProperty("foff", out var mfoff) && mfoff.ValueKind == JsonValueKind.Number)
                        m.FileOffset = mfoff.GetInt64();
                    foreach (var p in r.GetProperty("params").EnumerateArray())
                        m.Params.Add(new ParamRec
                        {
                            Name = p.GetProperty("n").GetString() ?? "",
                            Type = p.GetProperty("t").GetString() ?? "obj",
                        });
                    cur!.Methods.Add(m);
                    break;
                case "P":
                    cur!.Props.Add(new PropRec
                    {
                        Name = r.GetProperty("name").GetString() ?? "",
                        Row = r.GetProperty("row").GetInt32(),
                        Get = r.GetProperty("get").GetInt32(),
                        Set = r.GetProperty("set").GetInt32(),
                    });
                    break;
                case "A":
                    attrs.Add(new AttrRec
                    {
                        Token = r.GetProperty("tok").GetUInt32(),
                        Tdi = r.GetProperty("tdi").GetInt32(),
                        Name = r.GetProperty("name").GetString() ?? "",
                        Ctor = r.GetProperty("ctor").GetInt32(),
                    });
                    break;
                case "E":
                    cur!.Events.Add(new EventRec
                    {
                        Name = r.GetProperty("name").GetString() ?? "",
                        Row = r.GetProperty("row").GetInt32(),
                        Type = r.TryGetProperty("type", out var ety) && ety.ValueKind == JsonValueKind.String
                            ? (ety.GetString() ?? "obj") : "obj",
                        Add = r.GetProperty("add").GetInt32(),
                        Remove = r.GetProperty("remove").GetInt32(),
                        Raise = r.GetProperty("raise").GetInt32(),
                    });
                    break;
                case "I":
                    cur!.Ifaces.Add(r.GetProperty("iface").GetInt32());
                    break;
            }
        }
        return types;
    }

    static int Emit(List<TypeRec> types, List<AttrRec> attrs, string output)
    {
        var mb = new MetadataBuilder();
        // module + assembly
        var mvid = mb.GetOrAddGuid(Guid.NewGuid());
        mb.AddModule(0, mb.GetOrAddString("DummyDll.dll"), mvid, default, default);
        mb.AddAssembly(mb.GetOrAddString("DummyDll"), new Version(0, 0, 0, 0),
            default, default, (AssemblyFlags)0, AssemblyHashAlgorithm.None);

        // special type handles (all defined in this same module, like the IL2CPP metadata image set)
        int FindType(string ns, string name)
        {
            for (int i = 0; i < types.Count; i++)
                if (types[i].Ns == ns && types[i].Name == name) return i;
            return -1;
        }
        int objId = FindType("System", "Object");
        int vtId = FindType("System", "ValueType");
        int enumId = FindType("System", "Enum");
        if (objId < 0) throw new Exception("System.Object missing");
        var objHandle = MetadataTokens.TypeDefinitionHandle(objId + 1);
        var vtHandle = vtId >= 0 ? MetadataTokens.TypeDefinitionHandle(vtId + 1) : default;
        var enumHandle = enumId >= 0 ? MetadataTokens.TypeDefinitionHandle(enumId + 1) : default;

        // precompute row counts per type. `paramRows` is the MethodDef ParamList cursor (starts at
        // row 1 and advances as params are emitted); the total is only needed for the marker
        // attribute ctors, so keep it separate -- using one variable for both made every MethodDef
        // point at ParamList=total+1 (no method owned its parameters).
        int fieldRows = 1, methodRows = 1, paramRows = 1, paramTotal = 1;
        var fieldStart = new int[types.Count + 1];
        var methodStart = new int[types.Count + 1];
        for (int i = 0; i < types.Count; i++)
        {
            fieldStart[i] = fieldRows;
            methodStart[i] = methodRows;
            fieldRows += types[i].Fields.Count;
            methodRows += types[i].Methods.Count;
            foreach (var m in types[i].Methods) paramTotal += m.Params.Count;
        }
        fieldStart[types.Count] = fieldRows;
        methodStart[types.Count] = methodRows;

        // ---- TypeDef rows (in metadata order, so handle = id + 1) ----
        for (int i = 0; i < types.Count; i++)
        {
            var t = types[i];
            var ta = TypeAttributes.NotPublic;
            uint vis = (uint)(t.Flags & 0x7);
            if (vis == 1) ta = TypeAttributes.Public;
            EntityHandle baseType = default;
            if (i == 0)
            {
                ta = 0; // <Module>
            }
            else if (t.Kind == "interface")
            {
                ta |= TypeAttributes.Interface | TypeAttributes.Abstract;
            }
            else if (t.Kind == "struct")
            {
                ta |= TypeAttributes.Sealed;
                baseType = vtHandle;
            }
            else if (t.Kind == "enum")
            {
                ta |= TypeAttributes.Sealed;
                baseType = enumHandle;
            }
            else
            {
                if ((t.Flags & 0x80) != 0) ta |= TypeAttributes.Abstract;
                if ((t.Flags & 0x100) != 0) ta |= TypeAttributes.Sealed;
                baseType = t.Parent >= 0 && t.Parent < types.Count
                    ? MetadataTokens.TypeDefinitionHandle(t.Parent + 1)
                    : objHandle;
            }
            mb.AddTypeDefinition(ta,
                mb.GetOrAddString(t.Ns),
                mb.GetOrAddString(t.Name),
                baseType,
                MetadataTokens.FieldDefinitionHandle(fieldStart[i]),
                MetadataTokens.MethodDefinitionHandle(methodStart[i]));
        }

        // ---- GenericParam rows (arity from the metadata type name suffix) ----
        int genericParamRows = 0;
        foreach (var t in types)
        {
            int arity = ArityOf(t.Name);
            if (arity == 0) continue;
            var ownerTd = MetadataTokens.TypeDefinitionHandle(t.Id + 1);
            for (int k = 0; k < arity; k++)
            {
                mb.AddGenericParameter(ownerTd, GenericParameterAttributes.None,
                    mb.GetOrAddString("T" + (k + 1)), k);
                genericParamRows++;
            }
        }

        // ---- InterfaceImpl rows ----
        foreach (var t in types)
        {
            var owner = MetadataTokens.TypeDefinitionHandle(t.Id + 1);
            foreach (int f in t.Ifaces)
            {
                if (f < 0 || f >= types.Count) continue;
                mb.AddInterfaceImplementation(owner, MetadataTokens.TypeDefinitionHandle(f + 1));
            }
        }

        // ---- FieldDef rows ----
        foreach (var t in types)
        {
            foreach (var f in t.Fields)
            {
                var fa = (FieldAttributes)(f.Flags & 0x7)
                         | FieldAttributes.Static & ((FieldAttributes)f.Flags & FieldAttributes.Static);
                // map the reference tool behaviour: constants become plain static fields (we do not
                // emit Constant/Marshal tables in v1), so clear Literal/HasDefault/HasFieldMarshal.
                fa = (FieldAttributes)((uint)fa & ~0x40u & ~0x8000u & ~0x1000u);
                if ((f.Flags & 0x10) != 0) fa |= FieldAttributes.Static;
                if ((f.Flags & 0x20) != 0) fa |= FieldAttributes.InitOnly;
                var blob = new BlobBuilder();
                var fenc = new BlobEncoder(blob).FieldSignature();
                WriteSigType(fenc, f.Type, types);
                mb.AddFieldDefinition(fa, mb.GetOrAddString(f.Name), mb.GetOrAddBlob(blob));
            }
        }

        // ---- MethodDef rows + params ----
        var ilBuilder = new BlobBuilder();
        var bodyStream = new MethodBodyStreamEncoder(ilBuilder);
        int methodTotal = types.Sum(t => t.Methods.Count);
        var methodHandles = new MethodDefinitionHandle[methodTotal];
        int gmiCursor = 0;
        foreach (var t in types)
        {
            bool isIface = t.Kind == "interface";
            foreach (var me in t.Methods)
            {
                var ma = (MethodAttributes)(me.Flags & 0xFFFFu);
                ma &= ~MethodAttributes.PinvokeImpl;
                ma &= ~MethodAttributes.UnmanagedExport;
                MethodImplAttributes impl = MethodImplAttributes.IL;
                bool isStatic = (me.Flags & 0x10) != 0;
                if (isIface)
                {
                    ma = MethodAttributes.Public | MethodAttributes.Virtual | MethodAttributes.Abstract
                         | MethodAttributes.HideBySig | MethodAttributes.NewSlot;
                    if (isStatic) ma |= MethodAttributes.Static;
                }
                bool isAbstract = (ma & MethodAttributes.Abstract) != 0 || isIface;
                if (isAbstract && !isIface)
                {
                    ma |= MethodAttributes.Abstract;
                }
                BlobBuilder? sigBlob = null;
                {
                    var bb = new BlobBuilder();
                    var sig = new BlobEncoder(bb).MethodSignature(isInstanceMethod: !isStatic);
                    sig.Parameters(me.Params.Count, out var retEnc, out var parsEnc);
                    if (me.Ret == "v") retEnc.Void();
                    else
                    {
                        var re = retEnc.Type(me.Ret.StartsWith("&"));
                        WriteSigType(re, me.Ret.TrimStart('&'), types);
                    }
                    foreach (var p in me.Params)
                    {
                        var pe = parsEnc.AddParameter();
                        var enc = pe.Type(p.Type.StartsWith("&"));
                        WriteSigType(enc, p.Type.TrimStart('&'), types);
                    }
                    sigBlob = bb;
                }
                int bodyOffset = -1;
                if (!isAbstract)
                {
                    var enc = new InstructionEncoder(new BlobBuilder());
                    if (me.Ret == "v")
                    {
                        enc.OpCode(ILOpCode.Ret);
                    }
                    else
                    {
                        enc.OpCode(ILOpCode.Ldnull);
                        enc.OpCode(ILOpCode.Throw);
                    }
                    bodyOffset = bodyStream.AddMethodBody(enc, maxStack: 1);
                }
                methodHandles[gmiCursor++] = mb.AddMethodDefinition(ma, impl, mb.GetOrAddString(me.Name),
                    mb.GetOrAddBlob(sigBlob!), bodyOffset,
                    MetadataTokens.ParameterHandle(paramRows));
                for (int k = 0; k < me.Params.Count; k++)
                {
                    mb.AddParameter(0, mb.GetOrAddString(me.Params[k].Name), k + 1);
                    paramRows++;
                }
            }
        }

        // ---- Property table + PropertyMap + MethodSemantics (real metadata properties) ----
        // A property signature mirrors its accessor: getter -> (return type, index params);
        // set-only -> (last setter param type, remaining index params). Accessors are linked with
        // MethodSemantics rows, so PropertyDefinition.GetAccessors() resolves in decompilers.
        var allMethods = types.SelectMany(t => t.Methods).ToList();
        BlobHandle BuildPropertySig(MethodRec? get, MethodRec? set)
        {
            var acc = get ?? set!;
            bool instance = (acc.Flags & 0x10) == 0;
            string ret;
            List<string> pars;
            if (get != null)
            {
                ret = get.Ret;
                pars = get.Params.Select(p => p.Type).ToList();
            }
            else
            {
                var sp = set!.Params;
                ret = sp.Count > 0 ? sp[^1].Type : "obj";
                pars = sp.Take(Math.Max(0, sp.Count - 1)).Select(p => p.Type).ToList();
            }
            var bb = new BlobBuilder();
            var sig = new BlobEncoder(bb).PropertySignature(instance);
            sig.Parameters(pars.Count, out var retEnc, out var parsEnc);
            if (ret == "v")
            {
                WriteSigType(retEnc.Type(false), "obj", types);
            }
            else
            {
                var re = retEnc.Type(ret.StartsWith("&"));
                WriteSigType(re, ret.TrimStart('&'), types);
            }
            foreach (var pt in pars)
            {
                var pe = parsEnc.AddParameter();
                var enc = pe.Type(pt.StartsWith("&"));
                WriteSigType(enc, pt.TrimStart('&'), types);
            }
            return mb.GetOrAddBlob(bb);
        }
        int propRowsEmitted = 0, propMapRowsEmitted = 0;
        foreach (var t in types)
        {
            if (t.Props.Count == 0) continue;
            PropertyDefinitionHandle firstProp = default;
            foreach (var p in t.Props)
            {
                MethodRec? getM = p.Get >= 0 && p.Get < allMethods.Count ? allMethods[p.Get] : null;
                MethodRec? setM = p.Set >= 0 && p.Set < allMethods.Count ? allMethods[p.Set] : null;
                if (getM == null && setM == null) continue;
                var ph = mb.AddProperty(PropertyAttributes.None, mb.GetOrAddString(p.Name),
                    BuildPropertySig(getM, setM));
                if (firstProp.IsNil) firstProp = ph;
                if (getM != null) mb.AddMethodSemantics(ph, MethodSemanticsAttributes.Getter, methodHandles[p.Get]);
                if (setM != null) mb.AddMethodSemantics(ph, MethodSemanticsAttributes.Setter, methodHandles[p.Set]);
                propRowsEmitted++;
            }
            if (!firstProp.IsNil)
            {
                mb.AddPropertyMap(MetadataTokens.TypeDefinitionHandle(t.Id + 1), firstProp);
                propMapRowsEmitted++;
            }
        }

        // ---- Event table + EventMap + MethodSemantics (real metadata events) ----
        // The event type is a TypeDefOrRef coded index, so resolve it to a TypeDefinition handle
        // (core types fall back to their in-module System.* definitions).
        EntityHandle EventTypeHandle(string enc)
        {
            if (enc.StartsWith("t") && int.TryParse(enc.Substring(1), out int tid) && tid >= 0 && tid < types.Count)
                return MetadataTokens.TypeDefinitionHandle(tid + 1);
            string core = enc switch
            {
                "obj" => "Object", "str" => "String", "v" => "Void", "b" => "Boolean", "c" => "Char",
                "s8" => "SByte", "u8" => "Byte", "s16" => "Int16", "u16" => "UInt16",
                "s32" => "Int32", "u32" => "UInt32", "s64" => "Int64", "u64" => "UInt64",
                "f4" => "Single", "f8" => "Double", "ip" => "IntPtr", "up" => "UIntPtr",
                _ => "Object",
            };
            int cid = FindType("System", core);
            if (cid < 0) cid = objId;
            return MetadataTokens.TypeDefinitionHandle(cid + 1);
        }
        int eventRowsEmitted = 0, eventMapRowsEmitted = 0;
        foreach (var t in types)
        {
            if (t.Events.Count == 0) continue;
            EventDefinitionHandle firstEvent = default;
            foreach (var ev in t.Events)
            {
                var eh = mb.AddEvent(EventAttributes.None, mb.GetOrAddString(ev.Name), EventTypeHandle(ev.Type));
                if (firstEvent.IsNil) firstEvent = eh;
                if (ev.Add >= 0 && ev.Add < methodHandles.Length)
                    mb.AddMethodSemantics(eh, MethodSemanticsAttributes.Adder, methodHandles[ev.Add]);
                if (ev.Remove >= 0 && ev.Remove < methodHandles.Length)
                    mb.AddMethodSemantics(eh, MethodSemanticsAttributes.Remover, methodHandles[ev.Remove]);
                if (ev.Raise >= 0 && ev.Raise < methodHandles.Length)
                    mb.AddMethodSemantics(eh, MethodSemanticsAttributes.Raiser, methodHandles[ev.Raise]);
                eventRowsEmitted++;
            }
            if (!firstEvent.IsNil)
            {
                mb.AddEventMap(MetadataTokens.TypeDefinitionHandle(t.Id + 1), firstEvent);
                eventMapRowsEmitted++;
            }
        }

        // ---- Il2CppDummyDll-style custom attributes (Address / FieldOffset) ----
        int attrBaseId = FindType("System", "Attribute");
        EntityHandle attrBaseHandle = attrBaseId >= 0
            ? MetadataTokens.TypeDefinitionHandle(attrBaseId + 1) : objHandle;
        var attrCtors = new List<MethodDefinitionHandle>();
        // Same five marker types (and field layouts) as the bundled Il2CppDummyDll.dll:
        // AddressAttribute(RVA/Offset/VA/Slot), AttributeAttribute(Name/RVA/Offset),
        // FieldOffsetAttribute(Offset), MetadataOffsetAttribute(Offset), TokenAttribute(Token).
        var attrFieldNames = new[]
        {
            new[] { "RVA", "Offset", "VA", "Slot" },
            new[] { "Name", "RVA", "Offset" },
            new[] { "Offset" },
            new[] { "Offset" },
            new[] { "Token" },
        };
        var attrTypeNames = new[]
        {
            "AddressAttribute", "AttributeAttribute", "FieldOffsetAttribute",
            "MetadataOffsetAttribute", "TokenAttribute",
        };
        for (int ai = 0; ai < attrTypeNames.Length; ai++)
        {
            int firstField = fieldRows;
            int firstMethod = methodRows;
            mb.AddTypeDefinition(TypeAttributes.Public | TypeAttributes.Sealed,
                mb.GetOrAddString("Il2CppDummyDll"), mb.GetOrAddString(attrTypeNames[ai]), attrBaseHandle,
                MetadataTokens.FieldDefinitionHandle(firstField),
                MetadataTokens.MethodDefinitionHandle(firstMethod));
            foreach (var fn in attrFieldNames[ai])
            {
                var fbb = new BlobBuilder();
                new BlobEncoder(fbb).FieldSignature().String();
                mb.AddFieldDefinition(FieldAttributes.Public, mb.GetOrAddString(fn), mb.GetOrAddBlob(fbb));
                fieldRows++;
            }
            var sbb = new BlobBuilder();
            new BlobEncoder(sbb).MethodSignature(isInstanceMethod: true).Parameters(0, out var retEb, out _);
            retEb.Void();
            var bodyEnc = new InstructionEncoder(new BlobBuilder());
            bodyEnc.OpCode(ILOpCode.Ret);
            var ctor = mb.AddMethodDefinition(
                MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName,
                MethodImplAttributes.IL, mb.GetOrAddString(".ctor"), mb.GetOrAddBlob(sbb),
                bodyStream.AddMethodBody(bodyEnc, maxStack: 0), MetadataTokens.ParameterHandle(paramRows));
            methodRows++;
            attrCtors.Add(ctor);
        }
        var addressCtor = attrCtors[0];
        var attributeCtor = attrCtors[1];
        var fieldOffsetCtor = attrCtors[2];
        var tokenCtor = attrCtors[4];
        int customAttrCount = 0;
        static void WriteSerString(BlobBuilder bb, string value)
        {
            var bytes = System.Text.Encoding.UTF8.GetBytes(value);
            if (bytes.Length < 0x80)
            {
                bb.WriteByte((byte)bytes.Length);
            }
            else
            {
                int len = bytes.Length;
                bb.WriteByte((byte)(0x80 | (len & 0x3F)));
                bb.WriteByte((byte)(len >> 6));
            }
            bb.WriteBytes(bytes);
        }
        BlobHandle NamedArgsBlob((string Name, string Value)[] args)
        {
            var bb = new BlobBuilder();
            bb.WriteUInt16(0x0001);
            bb.WriteUInt16((ushort)args.Length);
            foreach (var (name, value) in args)
            {
                bb.WriteByte(0x53); // named argument: field
                bb.WriteByte(0x0E); // field type: string
                WriteSerString(bb, name);
                WriteSerString(bb, value);
            }
            return mb.GetOrAddBlob(bb);
        }
        foreach (var t in types)
        {
            foreach (var f in t.Fields)
            {
                if (f.Token == 0 || f.Offset is null) continue;
                var fh = MetadataTokens.FieldDefinitionHandle((int)(f.Token - 0x04000000));
                mb.AddCustomAttribute(fh, fieldOffsetCtor,
                    NamedArgsBlob(new[] { ("Offset", "0x" + f.Offset.Value.ToString("X")) }));
                customAttrCount++;
            }
            foreach (var me in t.Methods)
            {
                if (me.Token == 0 || me.Rva == 0) continue;
                var mh = MetadataTokens.MethodDefinitionHandle((int)(me.Token - 0x06000000));
                var args = new List<(string, string)>
                {
                    ("RVA", "0x" + me.Rva.ToString("X")),
                };
                if (me.FileOffset is long fo) args.Add(("Offset", "0x" + fo.ToString("X")));
                args.Add(("VA", "0x" + (0x140000000UL + me.Rva).ToString("X")));
                if (me.Slot is int sl && sl >= 0) args.Add(("Slot", sl.ToString()));
                mb.AddCustomAttribute(mh, addressCtor, NamedArgsBlob(args.ToArray()));
                customAttrCount++;
            }
        }

        // ---- TokenAttribute on every row-bearing member (matches DummyDllAddToken=true) ----
        foreach (var t in types)
        {
            var th = MetadataTokens.TypeDefinitionHandle(t.Id + 1);
            mb.AddCustomAttribute(th, tokenCtor,
                NamedArgsBlob(new[] { ("Token", "0x" + (0x02000001u + (uint)t.Id).ToString("X")) }));
            customAttrCount++;
            foreach (var f in t.Fields)
            {
                if (f.Token == 0) continue;
                var fh = MetadataTokens.FieldDefinitionHandle((int)(f.Token - 0x04000000));
                mb.AddCustomAttribute(fh, tokenCtor, NamedArgsBlob(new[] { ("Token", "0x" + f.Token.ToString("X")) }));
                customAttrCount++;
            }
            foreach (var me in t.Methods)
            {
                if (me.Token == 0) continue;
                var mh = MetadataTokens.MethodDefinitionHandle((int)(me.Token - 0x06000000));
                mb.AddCustomAttribute(mh, tokenCtor, NamedArgsBlob(new[] { ("Token", "0x" + me.Token.ToString("X")) }));
                customAttrCount++;
            }
            foreach (var p in t.Props)
            {
                var ph = MetadataTokens.PropertyDefinitionHandle(p.Row + 1);
                uint tok = 0x17000001u + (uint)p.Row;
                mb.AddCustomAttribute(ph, tokenCtor, NamedArgsBlob(new[] { ("Token", "0x" + tok.ToString("X")) }));
                customAttrCount++;
            }
            foreach (var ev in t.Events)
            {
                var eh = MetadataTokens.EventDefinitionHandle(ev.Row + 1);
                uint tok = 0x14000001u + (uint)ev.Row;
                mb.AddCustomAttribute(eh, tokenCtor, NamedArgsBlob(new[] { ("Token", "0x" + tok.ToString("X")) }));
                customAttrCount++;
            }
        }

        // ---- Recovered custom attribute instances ----
        // Restorable classes (exactly one method: a parameterless .ctor, the reference tool's rule)
        // get the real CustomAttribute; the rest get an AttributeAttribute marker carrying the
        // attribute class name (RVA/Offset omitted: they need runtime custom-attribute generators).
        EntityHandle MemberHandle(uint token)
        {
            int kind = (int)(token >> 24);
            int idx = (int)(token & 0xFFFFFF);
            if (idx < 1) return default;
            return kind switch
            {
                0x02 => idx <= types.Count ? MetadataTokens.TypeDefinitionHandle(idx) : default,
                0x04 => MetadataTokens.FieldDefinitionHandle(idx),
                0x06 => MetadataTokens.MethodDefinitionHandle(idx),
                0x08 => MetadataTokens.ParameterHandle(idx),
                0x17 => MetadataTokens.PropertyDefinitionHandle(idx),
                _ => default,
            };
        }
        var classAttrBlob = mb.GetOrAddBlob(new byte[] { 0x01, 0x00, 0x00, 0x00 });
        foreach (var a in attrs)
        {
            var member = MemberHandle(a.Token);
            if (member.IsNil) continue;
            if (a.Ctor >= 0 && a.Ctor < methodHandles.Length && !methodHandles[a.Ctor].IsNil)
            {
                mb.AddCustomAttribute(member, methodHandles[a.Ctor], classAttrBlob);
            }
            else
            {
                mb.AddCustomAttribute(member, attributeCtor, NamedArgsBlob(new[] { ("Name", a.Name) }));
            }
            customAttrCount++;
        }

        // ---- PE image ----
        var peHeader = new PEHeaderBuilder(
            machine: Machine.I386,
            imageCharacteristics: Characteristics.ExecutableImage | Characteristics.Dll);
        var peBuilder = new ManagedPEBuilder(peHeader, new MetadataRootBuilder(mb), ilBuilder);
        var blobOut = new BlobBuilder();
        peBuilder.Serialize(blobOut);
        File.WriteAllBytes(output, blobOut.ToArray());
        Console.WriteLine($"wrote {output} ({new FileInfo(output).Length / 1024} KB)");
        return customAttrCount;
    }

    static int ArityOf(string name)
    {
        int dot = name.LastIndexOf('.');
        string seg = dot >= 0 ? name.Substring(dot + 1) : name;
        int bt = seg.LastIndexOf('`');
        if (bt < 0) return 0;
        if (int.TryParse(seg.Substring(bt + 1), out int n) && n > 0 && n < 64) return n;
        return 0;
    }

    static void WriteSigType(SignatureTypeEncoder enc, string s, List<TypeRec> types)
    {
        if (s.StartsWith("p")) { WriteSigType(enc.Pointer(), s.Substring(1), types); return; }
        if (s.StartsWith("a")) { WriteSigType(enc.SZArray(), s.Substring(1), types); return; }
        switch (s)
        {
            case "v": enc.VoidPointer(); return;
            case "b": enc.Boolean(); return;
            case "c": enc.Char(); return;
            case "s8": enc.SByte(); return;
            case "u8": enc.Byte(); return;
            case "s16": enc.Int16(); return;
            case "u16": enc.UInt16(); return;
            case "s32": enc.Int32(); return;
            case "u32": enc.UInt32(); return;
            case "s64": enc.Int64(); return;
            case "u64": enc.UInt64(); return;
            case "f4": enc.Single(); return;
            case "f8": enc.Double(); return;
            case "str": enc.String(); return;
            case "ip": enc.IntPtr(); return;
            case "up": enc.UIntPtr(); return;
            case "obj": enc.Type(MetadataTokens.TypeDefinitionHandle(
                types.FindIndex(t => t.Ns == "System" && t.Name == "Object") + 1), false); return;
            case "tr": enc.TypedReference(); return;
        }
        if (s.StartsWith("t"))
        {
            int id = int.Parse(s.Substring(1));
            bool isValue = id >= 0 && id < types.Count &&
                (types[id].Kind == "struct" || types[id].Kind == "enum");
            enc.Type(MetadataTokens.TypeDefinitionHandle(id + 1), isValue);
            return;
        }
        // fallback: object
        enc.Type(MetadataTokens.TypeDefinitionHandle(types.FindIndex(t => t.Ns == "System" && t.Name == "Object") + 1), false);
    }

    static void Verify(string path, List<TypeRec> expected, List<AttrRec> attrs, int expectedCustomAttrs)
    {
        using var fs = File.OpenRead(path);
        using var pe = new PEReader(fs);
        var md = pe.GetMetadataReader();
        int typeCount = 0, fieldCount = 0, methodCount = 0, paramCount = 0, ifaceCount = 0, bodyCount = 0;
        foreach (var th in md.TypeDefinitions)
        {
            typeCount++;
            var td = md.GetTypeDefinition(th);
            foreach (var fh in td.GetFields()) { fieldCount++; }
            foreach (var mh in td.GetMethods())
            {
                methodCount++;
                var mdef = md.GetMethodDefinition(mh);
                if (mdef.RelativeVirtualAddress != 0) bodyCount++;
                foreach (var ph in mdef.GetParameters()) paramCount++;
            }
            foreach (var ih in td.GetInterfaceImplementations()) ifaceCount++;
        }
        int attrRowCount = md.CustomAttributes.Count;
        int genericParamRows = md.GetTableRowCount(TableIndex.GenericParam);
        int expGenericParams = expected.Sum(t => ArityOf(t.Name));
        Console.WriteLine($"verify: types={typeCount} fields={fieldCount} methods={methodCount} " +
                          $"params={paramCount} ifaces={ifaceCount} bodies={bodyCount} customAttrs={attrRowCount} genericParams={genericParamRows}");
        if (genericParamRows != expGenericParams) throw new Exception($"generic param count mismatch {genericParamRows} vs {expGenericParams}");
        // +5 marker types (Address/Attribute/FieldOffset/MetadataOffset/Token) with 10 fields and 5 ctors
        if (typeCount != expected.Count + 5) throw new Exception($"type count mismatch {typeCount} vs {expected.Count + 5}");
        int expFields = expected.Sum(t => t.Fields.Count) + 10;
        int expMethods = expected.Sum(t => t.Methods.Count) + 5;
        int expParams = expected.Sum(t => t.Methods.Sum(m => m.Params.Count));
        if (fieldCount != expFields) throw new Exception($"field count mismatch {fieldCount} vs {expFields}");
        if (methodCount != expMethods) throw new Exception($"method count mismatch {methodCount} vs {expMethods}");
        if (paramCount != expParams) throw new Exception($"param count mismatch {paramCount} vs {expParams}");
        // ---- property table check ----
        int propRows = md.GetTableRowCount(TableIndex.Property);
        int propMapRows = md.GetTableRowCount(TableIndex.PropertyMap);
        int semanticsRows = md.GetTableRowCount(TableIndex.MethodSemantics);
        int expProps = expected.Sum(t => t.Props.Count);
        int expPropMaps = expected.Count(t => t.Props.Count > 0);
        int expSemantics = expected.Sum(t => t.Props.Sum(p => (p.Get >= 0 ? 1 : 0) + (p.Set >= 0 ? 1 : 0)))
            + expected.Sum(t => t.Events.Sum(e => (e.Add >= 0 ? 1 : 0) + (e.Remove >= 0 ? 1 : 0) + (e.Raise >= 0 ? 1 : 0)));
        Console.WriteLine($"verify: properties={propRows} propertyMaps={propMapRows} methodSemantics={semanticsRows}");
        if (propRows != expProps) throw new Exception($"property count mismatch {propRows} vs {expProps}");
        if (propMapRows != expPropMaps) throw new Exception($"property map count mismatch {propMapRows} vs {expPropMaps}");
        if (semanticsRows != expSemantics) throw new Exception($"method semantics count mismatch {semanticsRows} vs {expSemantics}");
        {
            int checkedProps = 0;
            foreach (var ph in md.PropertyDefinitions)
            {
                var pd = md.GetPropertyDefinition(ph);
                var sig = md.GetBlobBytes(pd.Signature);
                if (sig.Length < 2 || (sig[0] & 0x08) == 0)
                    throw new Exception($"bad property signature for {md.GetString(pd.Name)}");
                var acc = pd.GetAccessors();
                if (acc.Getter.IsNil && acc.Setter.IsNil)
                    throw new Exception($"property {md.GetString(pd.Name)} has no accessor");
                if (checkedProps < 3)
                    Console.WriteLine($"  property sample: {md.GetString(pd.Name)} sig={sig.Length}B " +
                                      $"getter={(acc.Getter.IsNil ? "-" : "yes")} setter={(acc.Setter.IsNil ? "-" : "yes")}");
                checkedProps++;
            }
            Console.WriteLine($"verify: property table decoded OK ({checkedProps} rows, all have a signature and an accessor)");
        }
        // ---- event table check ----
        int eventRowsOut = md.GetTableRowCount(TableIndex.Event);
        int eventMapRowsOut = md.GetTableRowCount(TableIndex.EventMap);
        int expEvents = expected.Sum(t => t.Events.Count);
        int expEventMaps = expected.Count(t => t.Events.Count > 0);
        Console.WriteLine($"verify: events={eventRowsOut} eventMaps={eventMapRowsOut}");
        if (eventRowsOut != expEvents) throw new Exception($"event count mismatch {eventRowsOut} vs {expEvents}");
        if (eventMapRowsOut != expEventMaps) throw new Exception($"event map count mismatch {eventMapRowsOut} vs {expEventMaps}");
        {
            int checkedEvents = 0;
            foreach (var eh in md.EventDefinitions)
            {
                var ed = md.GetEventDefinition(eh);
                if (ed.Type.IsNil) throw new Exception($"event {md.GetString(ed.Name)} has no type");
                var eacc = ed.GetAccessors();
                if (eacc.Adder.IsNil && eacc.Remover.IsNil && eacc.Raiser.IsNil)
                    throw new Exception($"event {md.GetString(ed.Name)} has no accessor");
                if (checkedEvents < 3)
                    Console.WriteLine($"  event sample: {md.GetString(ed.Name)} add={(eacc.Adder.IsNil ? "-" : "yes")} " +
                                      $"remove={(eacc.Remover.IsNil ? "-" : "yes")} raise={(eacc.Raiser.IsNil ? "-" : "yes")}");
                checkedEvents++;
            }
            Console.WriteLine($"verify: event table decoded OK ({checkedEvents} rows, all have a type and an accessor)");
        }
        if (attrRowCount != expectedCustomAttrs)
            throw new Exception($"custom attribute count mismatch {attrRowCount} vs {expectedCustomAttrs} (emitter counted)");
        if (attrs.Count > 0 && expectedCustomAttrs <= 0) throw new Exception("attribute instances loaded but not emitted");
        {
            var ctorNames = new System.Collections.Generic.Dictionary<EntityHandle, string>();
            string CtorName(EntityHandle ctor)
            {
                if (!ctorNames.TryGetValue(ctor, out var n))
                {
                    var mdef = md.GetMethodDefinition((MethodDefinitionHandle)ctor);
                    n = md.GetString(md.GetTypeDefinition(mdef.GetDeclaringType()).Name);
                    ctorNames[ctor] = n;
                }
                return n;
            }
            int checkedAttrs = 0;
            var ctorHist = new System.Collections.Generic.Dictionary<string, int>();
            var sampleRows = new System.Collections.Generic.List<int>();
            for (int r = 1; r <= Math.Min(300, attrRowCount); r++) sampleRows.Add(r);
            for (int r = Math.Max(1, attrRowCount - 299); r <= attrRowCount; r++) sampleRows.Add(r);
            foreach (var row in sampleRows)
            {
                var ca = md.GetCustomAttribute(MetadataTokens.CustomAttributeHandle(row));
                string ctorName = CtorName(ca.Constructor);
                var blob = md.GetBlobBytes(ca.Value);
                if (blob.Length < 4 || blob[0] != 1 || blob[1] != 0)
                    throw new Exception($"custom attribute blob with bad prolog ({blob.Length} bytes, ctor {ctorName})");
                int named = blob[2] | (blob[3] << 8);
                if (named == 0)
                {
                    // A restorable attribute instance: prolog + zero named arguments.
                    if (blob.Length != 4) throw new Exception($"class attribute blob not 4 bytes (ctor {ctorName})");
                }
                else
                {
                    // Every emitted named argument is a string field; parse its name.
                    int p = 4;
                    if (blob.Length < p + 4 || blob[p] != 0x53 || blob[p + 1] != 0x0E)
                        throw new Exception($"bad named argument header (ctor {ctorName})");
                    p += 2;
                    int len = blob[p];
                    if ((len & 0x80) != 0) throw new Exception("unexpected long SerString name");
                    p++;
                    string argName = System.Text.Encoding.UTF8.GetString(blob, p, len);
                    if (argName is not ("RVA" or "Offset" or "VA" or "Slot" or "Token" or "Name"))
                        throw new Exception($"unexpected named argument {argName} (ctor {ctorName})");
                }
                ctorHist[ctorName] = ctorHist.GetValueOrDefault(ctorName) + 1;
                checkedAttrs++;
            }
            Console.WriteLine($"verify: custom attributes decoded OK (sample {checkedAttrs}/{attrRowCount}; ctors: " +
                              string.Join(", ", ctorHist.Select(kv => kv.Key + "=" + kv.Value)) + ")");
        }
        Console.WriteLine("verify: OK (counts match the JSONL export; attribute rows present)");
    }
}
