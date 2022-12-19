import { Request, Response } from "express";
import { auth, resolver, loaders } from "@iden3/js-iden3-auth";
import getRawBody from "raw-body";

const requestMap = new Map();

export const GetAuthRequest = async (req: Request<any>, res: Response<any>) => {
    // Audience is verifier id
    const hostUrl = "http://5281-240d-1a-767-6100-3c1e-a3ea-6d16-85cd.ngrok.io";
    const sessionId = 1;
    const callbackURL = "/api/callback";
    const audience = "1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ";

    const uri = `${hostUrl}${callbackURL}?sessionId=${sessionId}`;

    // Generate request for basic auth
    const request = auth.createAuthorizationRequestWithMessage(
        "test flow",
        "message to sign",
        audience,
        uri,
    );

    request.id = "7f38a193-0918-4a48-9fac-36adfdb8b542";
    request.thid = "7f38a193-0918-4a48-9fac-36adfdb8b542";

    // Add query-based request
    const proofRequest = {
        id: 1,
        circuit_id: "credentialAtomicQuerySig",
        rules: {
            query: {
                allowedIssuers: ["*"],
                schema: {
                    type: "sinsinpurinMember",
                    url: "https://s3.eu-west-1.amazonaws.com/polygonid-schemas/20bff757-9626-4cf5-8873-909a3dbab937.json-ld",
                },
                req: {
                    Role: {
                        $eq: 1,
                    },
                    iat: {
                        $lt: 21000101, // dateOfBirth field less then 2100/01/01
                    },
                },
            },
        },
    };

    const scope = request.body.scope ?? [];
    request.body.scope = [...scope, proofRequest];

    // Store zk request in map associated with session ID
    requestMap.set(`${sessionId}`, request);

    return res
        .status(200)
        .set("Content-Type", "application/json")
        .send(request);
};

// Callback verifies the proof after sign-in callbacks
export const Callback = async (req: Request<any>, res: Response<any>) => {
    // Get session ID from request
    const sessionId = req.query.sessionId;

    // extract proof from the request
    const raw = await getRawBody(req);
    const tokenStr = raw.toString().trim();

    // fetch authRequest from sessionID
    const authRequest = requestMap.get(`${sessionId}`);

    // Locate the directory that contains circuit's verification keys
    const verificationKeyloader = new loaders.FSKeyLoader("../keys");
    const sLoader = new loaders.UniversalSchemaLoader("ipfs.io");

    // Add Polygon Mumbai RPC node endpoint - needed to read on-chain state and identity state contract address
    const ethStateResolver = new resolver.EthStateResolver(
        "https://rpc-mumbai.maticvigil.com",
        "0x46Fd04eEa588a3EA7e9F055dd691C688c4148ab3",
    );

    // EXECUTE VERIFICATION
    const verifier = new auth.Verifier(
        verificationKeyloader,
        sLoader,
        ethStateResolver,
    );

    let authResponse;
    try {
        authResponse = await verifier.fullVerify(tokenStr, authRequest);
    } catch (error) {
        return res.status(500).send(error);
    }
    return res
        .status(200)
        .set("Content-Type", "application/json")
        .send(
            "user with ID: " + authResponse.from + " Succesfully authenticated",
        );
};
