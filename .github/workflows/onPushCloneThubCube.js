// actions on push on chub
const fs = require('fs');
const Octokit = require("@octokit/rest");
const axios = require("axios");
const shell = require("shelljs");
// const crypto = require('crypto');
const { createCipheriv, createDecipheriv, randomBytes } = require('crypto');

const inputEncoding = 'utf8';
const outputEncoding = 'hex';

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
        // return {
        //     result: true,
        //     decrypted: decrypted.toString()
        // }
    } catch (err) {
        console.log(err)
        throw err
    }
}

async function encryptAndPutAuthFile(username, repo, algorithm, gitToken, authPhrase, _silent) {
    try {
        // var cipher = crypto.createCipher(algorithm, gitToken);
        // var encryptedPhrase = cipher.update(authPhrase, 'utf8', 'hex');
        // encryptedPhrase += cipher.final('hex');
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
        // var decipher = crypto.createDecipher(algorithm, pwd);
        // var token = decipher.update(content, 'hex', 'utf8');
        // token += decipher.final('utf8');
        let token = await decrypt(content, algorithm, pwd);
        return token;
    } catch (err) {
        throw err
    }
}


async function cloneTrainerBuiltCube(bHub, repoName) {
    console.log(`Cloning from BHub...`);
    try {
        const cloneUrl = `https://github.com/${bHub}/${repoName}`;
        const _silent = false;
        shell.exec(`git clone ${cloneUrl}`, { silent: _silent });
        return {
            result: true
        }
    } catch (err) {
        return {
            result: false,
            error: err.message
        }
    }
}

async function createLessons(cube, lessons, repoName, token, bHub) {
    console.log(`Creating '${repoName}' lessons...`);
    const _silent = false;

    try {
        process.chdir(process.cwd() +  `/${repoName}`);

        for (let ix = 0; ix < lessons.length; ix++) {
            const lesson = lessons[ix];
            shell.exec(`git checkout --orphan ${lesson}`, { silent: _silent });
            shell.exec(`git rm -rf .`, { silent: _silent });
            shell.exec(`echo "${lesson}" > README.md`, { silent: _silent });
            shell.exec(`git add --all`, { silent: _silent });
            shell.exec(`git commit -m 'Initial ${lesson}'`, { silent: _silent });
        }

        shell.exec(`git checkout master`, { silent: _silent });

        cubeInfo = {};
        cubeInfo.index = lessons;
        fs.writeFileSync(`${cube}.cube.json`, JSON.stringify(cubeInfo, null, 4));
        
        shell.exec(`git add --all`, { silent: _silent });
        shell.exec(`git commit -m 'Add lessons'`, { silent: _silent });
        shell.exec(`git push https://${bHub}:${token}@github.com/${bHub}/${repoName}.git --all`, { silent: _silent });
        
        console.log(`Done.`);

        return {
            result: true
        }

    } catch (err) {
        return {
            result: false,
            error: err.message
        }
    }
}

async function forkBhubCube(username, repoName, bHub) {
    console.log("Forking to teacher repo...");
    try {
        // get teacher token
        const url = 'https://webhooks.mongodb-stitch.com/api/client/v2.0/app/kportal-grmuv/service/kportalWeb/incoming_webhook/getUserToken?secret=5eaae879cf';
        let response = await axios.post(url, {
            "username": username
        });
        let token = response.data['token'];
        let octokit = new Octokit({
            auth: "token " + token
        });
        await octokit.repos.createFork({
            owner: bHub,
            repo: repoName
        });

        return {
            result: true,
            repoLink: `https://github.com/${username}/${repoName}`
        }
    } catch (err) {
        return {
            result: false,
            error: err.message
        }
    }
}

async function enablePage(username, repoName) {
    console.log("Enable git page...");
    try {
        // get teacher token
        const url = 'https://webhooks.mongodb-stitch.com/api/client/v2.0/app/kportal-grmuv/service/kportalWeb/incoming_webhook/getUserToken?secret=5eaae879cf';
        let response = await axios.post(url, {
            "username": username
        });
        let token = response.data['token'];
        let octokit = new Octokit({
            auth: "token " + token
        });
        
        // enable page
        await octokit.repos.enablePagesSite({
            owner: username,
            repo: repoName,
            source: {
                "branch": "master",
                "path": "/docs"
            },
            headers: {
                accept: "application/vnd.github.switcheroo-preview+json"
            }
        })

        console.log("Done.");
        return {
            result: true,
            repoLink: `https://github.com/${username}/${repoName}`
        }
    } catch (err) {
        return {
            result: false,
            error: "Couldn't enable page: " + err.message
        }
    }
}

// async function addCollaborator(owner, repo, collaborator, token) {
//     console.log("Add collaborator...");
//     try {
//         let octokit = new Octokit({
//             auth: "token " + token
//         });
//         // add collaborator
//         let res = await octokit.repos.addCollaborator({
//             owner,
//             repo,
//             username: collaborator
//         })
//         // accept invitation
//         await axios.post(
//             'https://webhooks.mongodb-stitch.com/api/client/v2.0/app/kportal-grmuv/service/kportalWeb/incoming_webhook/acceptGitInvitation?secret=secret', {
//             "invitation_id": res.data.id,
//             "username": collaborator
//         });
//         console.log("Done.");
//         return true;
//     } catch (err) {
//         return {
//             result: false,
//             error: "Couldn't add collaborator: " + err.message
//         }
//     }
// }

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

let initCube = async (username, cube, lessons, repo, gitToken) => {
    const algorithm = 'aes256';
    const authPhrase = 'unclecode';
    const server = "https://cubie.now.sh";
    const bHub = 'kportal-hub';
    const _silent = false;

    try {
        const repoName = `${username}-${cube}-build`;

        // create encrypted auth file and send it to server to get tokens
        await encryptAndPutAuthFile(bHub, repo, algorithm, gitToken, authPhrase, _silent);

        // get token from server
        let authRes = (await axios.post(server + "/api/check-auth", {
            username,
            gitToken,
            repo: repoName,
            path: `auth`,
            type: "c"
        })).data;
        if (!authRes.result) {
            throw new Error("Unauthorized Access")
            // return false;
        } else {
            let r = await getUserTokenAndDecrypt(repo, algorithm, gitToken);
            // const teacherToken = r.split('\n')[0].split('=')[1]
            const masterToken = r.split('\n')[1].split('=')[1]

            // ============================================== func 1 - clone cube from thub 
            let res = await cloneTrainerBuiltCube(bHub, repoName);
            if (res.result) {
                // ========================================== func 2 - create a branch for each lesson
                await createLessons(cube, lessons, repoName, masterToken, bHub);
                
                // ========================================== func 3 - delete auth file
                await deleteFile(
                    bHub, // owner
                    repoName, // repo
                    "auth", // path
                    "delete auth file",
                    "master", // branch
                    masterToken
                );

                // ========================================== func 4 - delete cube.user.json
                await deleteFile(
                    bHub, // owner
                    repoName, // repo
                    `${cube}.user.json`, // path
                    `delete ${cube}.user.json`,
                    "master", // branch
                    masterToken
                );

                // ========================================== func 5 - fork cube repo for teacher
                await forkBhubCube(username, repoName, bHub);

                // ========================================== func 6 - add collaborator
                // await addCollaborator(username, repoName, collaborator, teacherToken);

                // ========================================== func 7 - enable page
                let resp = await enablePage(username, repoName);

                return resp;
            }
            return res;
        }

    } catch (err) {
        console.log(`Couldn't create and fetch cube for ${cube}`, err)
        return false;
    }
}

const cubeOnPush = async (repo, gitToken) => {
    const commit = JSON.parse(fs.readFileSync(process.env.NODE_CUBE, 'utf8')).commits[0].message;
    // const cube = JSON.parse(fs.readFileSync(process.env.NODE_CUBE, 'utf8')).commits[0].message.split(".")[0];
    const cube = commit.split(".")[0];
    if (!commit.toLocaleLowerCase().startsWith('delete')) {
        const username = JSON.parse(fs.readFileSync(`${cube}.user.json`, 'utf8')).username;
        const lessons = JSON.parse(fs.readFileSync(`${cube}.user.json`, 'utf8')).lessons;
        return await initCube(username, cube, lessons, repo, gitToken);
    }
    return "no actions to trigger";
}

cubeOnPush(process.argv[2], process.argv[3]).then((res) => {
    console.log(res)
})
