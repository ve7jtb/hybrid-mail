#!/usr/bin/env python3
import plistlib,sys
from pathlib import Path
path=Path(sys.argv[1])/'Contents/Info.plist'
p=plistlib.loads(path.read_bytes())
p['CFBundleDocumentTypes']=[{'CFBundleTypeName':'PQ Mail public certificate bundle','CFBundleTypeRole':'Viewer','LSHandlerRank':'Owner','LSItemContentTypes':['org.pqmail.certificates']}]
p['UTExportedTypeDeclarations']=[{'UTTypeIdentifier':'org.pqmail.certificates','UTTypeDescription':'PQ Mail public certificate bundle','UTTypeConformsTo':['public.data'],'UTTypeTagSpecification':{'public.filename-extension':['pqcert'],'public.mime-type':['application/vnd.pqmail.certificates']}}]
path.write_bytes(plistlib.dumps(p))
