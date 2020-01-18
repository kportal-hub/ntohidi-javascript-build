const fs = require('fs');
const Octokit = require("@octokit/rest");
const axios = require("axios");
const shell = require("shelljs");
const { createCipheriv, createDecipheriv, randomBytes } = require('crypto');

const inputEncoding = 'utf8';
const outputEncoding = 'hex';
const server = "https://cubie.now.sh";

async function encrypt(content, algorithm, key) {
    try {
        key = key.substr(key.length - 32);
        const iv = new Buffer.from(randomBytes(16), 'hex');
        const cipher = createCipheriv(algorithm, key, iv);
        let crypted = cipher.update(content, inputEncoding, outputEncoding);
        crypted += cipher.final(outputEncoding);
        return `${iv.toString('hex')}:${crypted.toString()}`;
    } catch (err) {
        console.log(err.message);
        throw err
    }
}

async function decrypt(content, algorithm, key) {
    try {
        key = key.substr(key.length - 32);
        const textParts = content.split(':');
        const IV = new Buffer.from(textParts.shift(), outputEncoding);
        const encryptedText = new Buffer.from(textParts.join(':'), outputEncoding);
        const decipher = createDecipheriv(algorithm, key, IV);
        let decrypted = decipher.update(encryptedText, outputEncoding, inputEncoding);
        decrypted += decipher.final(inputEncoding);
        return decrypted.toString()
    } catch (err) {
        console.log(err)
        throw err
    }
}

async function encryptAndPutAuthFile(username, repo, algorithm, gitToken, authPhrase, _silent) {
    try {
        let encryptedPhrase = await encrypt(authPhrase, algorithm, gitToken)
        shell.exec(`git checkout master`, {silent: _silent});
        shell.exec(`echo ${encryptedPhrase} > auth`, {silent: _silent});
        shell.exec(`git add auth`, {silent: _silent});
        shell.exec(`git commit -m 'add auth file'`, {silent: _silent});
        shell.exec(`git push https://${username}:${gitToken}@github.com/${repo} master`, {silent: _silent});
        return true
    } catch (err) {
        throw err
    }
}

async function getUserTokenAndDecrypt(repo, algorithm, pwd) {
    try {
        let resp = await axios.get(`https://api.github.com/repos/${repo}/contents/auth`);
        if(!resp.data.content)
            throw new Error("No auth file found");
        let content = Buffer.from(resp.data.content, 'base64').toString('ascii').replace(/\n/g, "");
        let token = await decrypt(content, algorithm, pwd);
        return token;
    } catch (err) {
        throw err
    }
}

async function fetchCubeInfo(owner, repo, path, token) {
    console.log("Getting cube info...");
    try {
        let octokit = new Octokit({
            auth: "token " + token
        });
        let cubeInfo = await octokit.repos.getContents({
            owner,
            repo,
            path,
            headers: {
                'accept': 'application/vnd.github.VERSION.raw'
            }
        });
        return {
            result: true,
            cubeInfo: JSON.parse(cubeInfo.data)
        }
    } catch (err) {
        return {
            result: false,
            error: "Couldn't get Cube info: " + err.message
        }
    }
}

async function deleteFile(owner, repo, path, message, branch, token) {
    try {
        let octokit = new Octokit({
            auth: "token " + token
        });
        let sha = (await octokit.repos.getContents({
            owner,
            repo,
            path,
            ref: branch
        })).data.sha;
        if (sha) {
            await octokit.repos.deleteFile({
                owner,
                repo,
                path,
                message,
                sha,
                branch
            });
            return true;
        } else {
            throw new Error(" no sha found to remove auth file in master branch in " + repo + "repo!");
        }
    } catch (err) {
        throw err
    }
}

async function addLessonBranches(qHub, repo, publishedRepo, lessenBranches, masterToken, silent) {
    console.log(`Create lesson branches...`);
    try {
        shell.exec(`git checkout master`, { silent });
        const cloneUrl = `https://github.com/${qHub}/${publishedRepo}`;
        shell.exec(`mkdir ${process.cwd()}/cubeRepo`, { silent });
        shell.exec(`git clone ${cloneUrl} cubeRepo`, { silent });
        process.chdir(`${process.cwd()}/cubeRepo`);
        for (let ix = 0; ix < lessenBranches.length; ix++) {
            const lessonBranch = lessenBranches[ix];
            console.log(`Create new branch ${lessonBranch}...`);
            shell.exec(`git checkout --orphan ${lessonBranch}`, { silent });
            shell.exec(`git rm -rf .`, { silent });
            shell.exec(`git pull https://${qHub}:${masterToken}@github.com/${qHub}/${publishedRepo}.git ${lessonBranch}`, { silent });
            shell.exec(`git push https://${qHub}:${masterToken}@github.com/${qHub}/${repo}.git ${lessonBranch}`, { silent });
        }
        console.log(`Done.`);
        return true;
    } catch(err){
        throw err
    }
}

let initCube = async (username, cube, repo, gitToken) => {
    const algorithm = 'aes256';
    const authPhrase = 'unclecode';
    const qHub = 'kportal-hub'; 
    const _silent = false;
    
    const publishedQHubCube = `${username}-${cube}-build`; 
    const qHubCube = `${cube}-qhub`; 
    
    try {
        // create encrypted auth file and send it to server to get tokens
        await encryptAndPutAuthFile(qHub, repo, algorithm, gitToken, authPhrase, _silent);

        // get token from server
        let authRes = (await axios.post(server + "/api/check-auth", {
            username,
            gitToken,
            repo: publishedQHubCube,
            path: `auth`,
            type: "c"
        })).data;
        
        if (!authRes.result) {
            await deleteFile(
                qHub, // owner
                publishedQHubCube, // repo
                "auth", // path
                "Delete auth request file",
                "master", // branch
                gitToken
            );
            await deleteFile(
                qHub, // owner
                publishedQHubCube, // repo
                "auth-req", // path
                "Delete auth request file",
                "master", // branch
                gitToken
            );
            throw new Error("Unauthorized Access");

        } else {

            let r = await getUserTokenAndDecrypt(repo, algorithm, gitToken);
            const masterToken = r.split('\n')[1].split('=')[1]

            // ========================================== func 1 - get cube info
            let res = await fetchCubeInfo(
                qHub, //owner
                publishedQHubCube, // repo
                `${cube}.cube.json`, // path
                masterToken
            );

            if (res.result) {
                let lessonBranches = Object.keys(res.cubeInfo.result);

                // ========================================== func 2 - creat lesson branches
                await addLessonBranches(
                    qHub, 
                    qHubCube,
                    publishedQHubCube, // publishedRepo
                    lessonBranches,
                    masterToken, 
                    _silent
                );

                // ========================================== func 3 - delete auth file
                await deleteFile(
                    qHub, // owner
                    publishedQHubCube, // repo
                    "auth", // path
                    "Delete auth request file",
                    "master", // branch
                    masterToken
                );
                // ========================================== func 4 - delete auth-req file
                await deleteFile(
                    qHub, // owner
                    publishedQHubCube, // repo
                    "auth-req", // path
                    "Delete auth-req request file",
                    "master", // branch
                    masterToken
                );
                
                console.log("Done.");
                return true;
            }

            console.log("No lesson branches found to create and add ")
            return false;
        }
        
    }
    catch(err){
        try {
            await deleteFile(
                qHub, // owner
                publishedQHubCube, // repo
                "auth", // path
                "Delete auth request file",
                "master", // branch
                gitToken
            );
            await deleteFile(
                qHub, // owner
                publishedQHubCube, // repo
                "auth-req", // path
                "Delete auth-req request file",
                "master", // branch
                gitToken
            );
        } catch (e) {
            console.log('[Catch] Could not delete auth files: ')
        }
        console.log(`Couldn't create and fetch lesson branches for ${cube}`, err )
        return false;
    }
}

const cubeOnPush = async (repo, gitToken) => {
    console.log(repo)
    const commit = JSON.parse(fs.readFileSync(process.env.NODE_CUBE, 'utf8')).commits[0].message;
    if (commit.toLocaleLowerCase() === "create new cube") {
        const data = JSON.parse(fs.readFileSync(`auth-req`, 'utf8'));
        let username = data.username;
        let cube = data.cube;
        return await initCube(username, cube, repo, gitToken);
    }
    return "No actions to run";
}

cubeOnPush(process.argv[2], process.argv[3]).then((res) => {
    console.log(res)
})