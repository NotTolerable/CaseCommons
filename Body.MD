# Report body persistence checklist

If report bodies still do not persist after the latest fixes, confirm the steps below:

1) Quill availability  
   - The admin report editor depends on the Quill CDN. If the CDN is blocked, the fallback copies the raw HTML from the editor div. Ensure the page loads without console errors; if the CDN is blocked by a network policy, mirror the assets locally or allow `https://cdn.jsdelivr.net/npm/quill@1.3.7`.

2) Hidden body field population  
   - Inspect the form before submit and confirm the hidden `body` field (`#bodyInput`) has the expected HTML. If it stays empty, check for JavaScript errors that might stop the submit handler.

3) Form caching / ad blockers  
   - Some privacy extensions block inline editors. Temporarily disable them and retest.

4) Database / migrations  
   - Ensure migrations are current: `flask db upgrade`.

If the body field is populated in the DOM but the saved report remains empty, capture the request payload (e.g., via browser devtools) to confirm the server receives `body`. If not, ensure the submit handler is firing; if yes, check server logs for request parsing errors. 
