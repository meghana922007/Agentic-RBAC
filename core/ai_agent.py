import google.generativeai as genai
import os

def call_gemini_to_fix(errors_list, broken_code, api_key=None):
    """
    Calls the Gemini API to fix the RBAC code based on the errors.
    Returns the patched RBAC code.
    """
    if not api_key:
        api_key = os.environ.get("GEMINI_API_KEY")
        
    if not api_key:
        return broken_code, "Error: GEMINI_API_KEY is not set. Please provide an API key."

    try:
        genai.configure(api_key=api_key)
        
        prompt = f"""You are a Security Architect. 
Your task is to fix the following RBAC DSL code to resolve the errors listed below.
Return ONLY the corrected RBAC code. Do not include markdown formatting like ```rbac or ```.
Do not include any explanations.

ERRORS:
{chr(10).join(errors_list)}

BROKEN CODE:
{broken_code}
"""
        models_to_try = [
            'models/gemini-3-flash-preview',
            'models/gemini-2.5-flash',
            'models/gemini-2.5-pro',
            'models/gemini-2.0-flash',
            'models/gemini-1.5-pro',
            'models/gemini-1.5-flash',
            'models/gemini-pro-latest',
            'models/gemini-flash-latest'
        ]
        response = None
        errors = []
        
        for model_name in models_to_try:
            try:
                model = genai.GenerativeModel(model_name)
                response = model.generate_content(prompt)
                break
            except Exception as e:
                errors.append(f"{model_name}: {str(e)}")
                continue
                
        if not response:
            last_error_details = "\n".join(errors)
            try:
                available_models = [m.name for m in genai.list_models() if 'generateContent' in m.supported_generation_methods]
                models_str = ", ".join(available_models) if available_models else "None found"
                raise Exception(f"All tried models failed.\n\nAttempts:\n{last_error_details}\n\nAvailable models for your API key: {models_str}")
            except Exception as e2:
                raise Exception(f"All tried models failed.\n\nAttempts:\n{last_error_details}\n\nCould not fetch available models: {str(e2)}")

        patched_code = response.text.strip()
        
        # Remove markdown blocks if the model accidentally includes them
        if patched_code.startswith("```"):
            lines = patched_code.split("\n")
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines[-1].startswith("```"):
                lines = lines[:-1]
            patched_code = "\n".join(lines).strip()
            
        return patched_code, None
        
    except Exception as e:
        return broken_code, f"API Error: {str(e)}"
